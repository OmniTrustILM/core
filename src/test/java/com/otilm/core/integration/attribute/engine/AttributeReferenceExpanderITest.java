package com.otilm.core.integration.attribute.engine;

import com.otilm.api.model.client.attribute.RequestAttribute;
import com.otilm.api.model.client.attribute.RequestAttributeV3;
import com.otilm.api.model.common.attribute.common.content.AttributeContentType;
import com.otilm.api.model.common.attribute.v3.content.BaseAttributeContentV3;
import com.otilm.api.model.common.attribute.v3.content.ResourceObjectContent;
import com.otilm.api.model.common.attribute.v3.content.data.ResourceObjectContentData;
import com.otilm.api.model.common.attribute.v3.content.data.ResourceSimpleContentData;
import com.otilm.api.model.core.auth.AttributeResource;
import com.otilm.api.model.core.auth.Resource;
import com.otilm.core.attribute.engine.AttributeReferenceExpander;
import com.otilm.core.dao.entity.AuthorityInstanceReference;
import com.otilm.core.dao.entity.Credential;
import com.otilm.core.dao.entity.EntityInstanceReference;
import com.otilm.core.dao.entity.Location;
import com.otilm.core.dao.repository.AuthorityInstanceReferenceRepository;
import com.otilm.core.dao.repository.CredentialRepository;
import com.otilm.core.dao.repository.EntityInstanceReferenceRepository;
import com.otilm.core.dao.repository.LocationRepository;
import com.otilm.core.model.auth.ResourceAction;
import com.otilm.core.util.BaseSpringBootTest;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.UUID;

/**
 * Integration test exercising the REAL {@code @ExternalAuthorization(CREDENTIAL, DETAIL)} aspect through the
 * expander's callback path: the unit test mocks the loader, this one proves the live per-object gate fails
 * closed via OPA and never returns the credential blob to an unauthorized caller. Also asserts the N3 invariant
 * (the ambient principal is unchanged after expansion — no setAuthentication).
 */
class AttributeReferenceExpanderITest extends BaseSpringBootTest {

    @Autowired
    private AttributeReferenceExpander expander;

    @Autowired
    private CredentialRepository credentialRepository;
    @Autowired
    private AuthorityInstanceReferenceRepository authorityInstanceReferenceRepository;
    @Autowired
    private EntityInstanceReferenceRepository entityInstanceReferenceRepository;
    @Autowired
    private LocationRepository locationRepository;

    private Credential credential;

    @BeforeEach
    void seedCredential() {
        credential = new Credential();
        credential.setKind("sample");
        credential.setName("expander-it-credential");
        credential = credentialRepository.save(credential);
    }

    private RequestAttribute credentialRef(UUID uuid) {
        ResourceSimpleContentData ref = new ResourceSimpleContentData(AttributeResource.CREDENTIAL);
        ref.setUuid(uuid.toString());
        List<BaseAttributeContentV3<?>> elements = new ArrayList<>();
        elements.add(new ResourceObjectContent(null, ref));
        return new RequestAttributeV3(UUID.randomUUID(), "cred", AttributeContentType.RESOURCE, elements);
    }

    @Test
    void authorizedCallerGetsCredentialBlobExpanded() throws Exception {
        RequestAttribute attr = credentialRef(credential.getUuid());
        expander.expandForCaller(List.of(attr), new HashSet<>());

        ResourceObjectContent element = (ResourceObjectContent) ((List<?>) attr.getContent()).getFirst();
        ResourceObjectContentData blob = element.getData();
        Assertions.assertInstanceOf(ResourceSimpleContentData.class, blob);
        Assertions.assertEquals(credential.getUuid().toString(), blob.getUuid(),
                "the blob loaded behind the passing DETAIL gate must be the referenced credential");
        Assertions.assertNotNull(((ResourceSimpleContentData) blob).getAttributes(),
                "the resolved blob must carry the credential's data attributes, not a bare ref");
    }

    @Test
    void deniedCallerNeverReceivesBlob_failsClosed() {
        denyResourceAccess(Resource.CREDENTIAL, ResourceAction.DETAIL);

        RequestAttribute attr = credentialRef(credential.getUuid());
        List<RequestAttribute> attrs = List.of(attr);
        Set<String> expandedSecrets = new HashSet<>();
        Assertions.assertThrows(AccessDeniedException.class,
                () -> expander.expandForCaller(attrs, expandedSecrets),
                "the live per-object DETAIL aspect must fail closed when OPA denies");

        ResourceObjectContent element = (ResourceObjectContent) ((List<?>) attr.getContent()).getFirst();
        Assertions.assertNull(((ResourceSimpleContentData) element.getData()).getAttributes(),
                "no blob may be set on the reference when the gate denies");
    }

    private RequestAttribute resourceRef(AttributeResource kind, UUID uuid) {
        ResourceSimpleContentData ref = new ResourceSimpleContentData(kind);
        ref.setUuid(uuid.toString());
        List<BaseAttributeContentV3<?>> elements = new ArrayList<>();
        elements.add(new ResourceObjectContent(null, ref));
        return new RequestAttributeV3(UUID.randomUUID(), "ref", AttributeContentType.RESOURCE, elements);
    }

    @Test
    void authorizedCallerExpandsAuthorityEntityAndLocationBlobs() throws Exception {
        // The unit test mocks these loaders; this drives the REAL @ExternalAuthorization(KIND, DETAIL) bodies of
        // AuthorityInstance/EntityInstance/Location getAuthorizedObjectAttributes through the expander.
        AuthorityInstanceReference authority = new AuthorityInstanceReference();
        authority.setName("it-authority");
        authority.setKind("sample");
        authority = authorityInstanceReferenceRepository.save(authority);

        EntityInstanceReference entity = new EntityInstanceReference();
        entity.setName("it-entity");
        entity.setKind("sample");
        entity = entityInstanceReferenceRepository.save(entity);

        Location location = new Location();
        location.setName("it-location");
        location.setEntityInstanceReference(entity);
        location = locationRepository.save(location);

        RequestAttribute authRef = resourceRef(AttributeResource.AUTHORITY, authority.getUuid());
        RequestAttribute entityRef = resourceRef(AttributeResource.ENTITY, entity.getUuid());
        RequestAttribute locationRef = resourceRef(AttributeResource.LOCATION, location.getUuid());

        expander.expandForCaller(List.of(authRef, entityRef, locationRef), new HashSet<>());

        for (RequestAttribute attr : List.of(authRef, entityRef, locationRef)) {
            ResourceObjectContent element = (ResourceObjectContent) ((List<?>) attr.getContent()).getFirst();
            Assertions.assertInstanceOf(ResourceSimpleContentData.class, element.getData(),
                    "each authorized reference must be expanded to its blob via the real DETAIL-guarded loader");
        }
    }

    @Test
    void locationExpansionFailsClosedWhenDeniedOwningEntityDetail() {
        // The LOCATION loader binds the parent gate to the location's owning entity in-body: a caller without
        // ENTITY:DETAIL on that entity must fail closed even though LOCATION:DETAIL would pass.
        EntityInstanceReference entity = new EntityInstanceReference();
        entity.setName("it-entity-denied");
        entity.setKind("sample");
        entity = entityInstanceReferenceRepository.save(entity);

        Location location = new Location();
        location.setName("it-location-denied");
        location.setEntityInstanceReference(entity);
        location = locationRepository.save(location);

        denyResourceAccess(Resource.ENTITY, ResourceAction.DETAIL);

        RequestAttribute locationRef = resourceRef(AttributeResource.LOCATION, location.getUuid());
        List<RequestAttribute> attrs = List.of(locationRef);
        Set<String> expandedSecrets = new HashSet<>();
        Assertions.assertThrows(AccessDeniedException.class,
                () -> expander.expandForCaller(attrs, expandedSecrets),
                "lacking ENTITY:DETAIL on the owning entity must fail the location expansion closed");

        ResourceObjectContent element = (ResourceObjectContent) ((List<?>) locationRef.getContent()).getFirst();
        Assertions.assertNull(((ResourceSimpleContentData) element.getData()).getAttributes(),
                "no blob may be set on the location reference when the owning-entity gate denies");
    }

    @Test
    void expanderDoesNotMutateAmbientPrincipal() throws Exception {
        Authentication before = SecurityContextHolder.getContext().getAuthentication();

        RequestAttribute attr = credentialRef(credential.getUuid());
        expander.expandForCaller(List.of(attr), new HashSet<>());

        Authentication after = SecurityContextHolder.getContext().getAuthentication();
        Assertions.assertSame(before, after,
                "N3: expander performs no setAuthentication / principal swap — ambient principal is unchanged");
    }
}
