package com.otilm.core.attribute.engine;

import com.otilm.api.model.client.attribute.RequestAttribute;
import com.otilm.api.model.client.attribute.RequestAttributeV3;
import com.otilm.api.model.common.attribute.common.content.AttributeContentType;
import com.otilm.api.model.common.attribute.v3.content.BaseAttributeContentV3;
import com.otilm.api.model.common.attribute.v3.content.ResourceObjectContent;
import com.otilm.api.model.common.attribute.v3.content.data.ResourceObjectContentData;
import com.otilm.api.model.common.attribute.v3.content.data.ResourceSimpleContentData;
import com.otilm.api.model.core.auth.AttributeResource;
import com.otilm.api.model.core.auth.Resource;
import com.otilm.core.dao.entity.Credential;
import com.otilm.core.dao.repository.CredentialRepository;
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
class AttributeReferenceExpanderIntegrationTest extends BaseSpringBootTest {

    @Autowired
    private AttributeReferenceExpander expander;

    @Autowired
    private CredentialRepository credentialRepository;

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
        Assertions.assertThrows(AccessDeniedException.class,
                () -> expander.expandForCaller(List.of(attr), new HashSet<>()),
                "the live per-object DETAIL aspect must fail closed when OPA denies");

        ResourceObjectContent element = (ResourceObjectContent) ((List<?>) attr.getContent()).getFirst();
        Assertions.assertNull(((ResourceSimpleContentData) element.getData()).getAttributes(),
                "no blob may be set on the reference when the gate denies");
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
