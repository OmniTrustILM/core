package com.otilm.core.attribute.engine;

import com.otilm.api.exception.AttributeException;
import com.otilm.api.model.client.attribute.RequestAttribute;
import com.otilm.api.model.client.attribute.RequestAttributeV3;
import com.otilm.api.model.client.attribute.ResponseAttributeV3;
import com.otilm.api.model.common.attribute.common.AttributeType;
import com.otilm.api.model.common.attribute.common.AttributeVersion;
import com.otilm.api.model.common.attribute.common.content.AttributeContentType;
import com.otilm.api.model.common.attribute.v3.content.BaseAttributeContentV3;
import com.otilm.api.model.common.attribute.v3.content.ResourceObjectContent;
import com.otilm.api.model.common.attribute.v3.content.data.ResourceObjectContentData;
import com.otilm.api.model.common.attribute.v3.content.data.ResourceSecretContentData;
import com.otilm.api.model.common.attribute.v3.content.data.ResourceSimpleContentData;
import com.otilm.api.model.core.auth.AttributeResource;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.UUID;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentMatchers;
import org.springframework.security.access.AccessDeniedException;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * Security-heavy unit tests for the callback-mode reference expander. The DETAIL gate itself is exercised through the
 * registry's loader (mocked to throw {@link AccessDeniedException} for "denied" objects), so these tests assert the
 * expander's fail-closed, cycle, depth, multi-select and pass-through behaviour without a Spring context. The real
 * per-object aspect is covered by the ArchUnit fence + the guarded loaders' own annotations.
 */
class AttributeReferenceExpanderTest {

    private CallerAuthorizedReferenceLoaderRegistry registry;
    private OutboundSecretContainment containment;
    private AttributeReferenceExpander expander;

    private final Set<String> expandedSecrets = new HashSet<>();

    @BeforeEach
    void setUp() {
        registry = mock(CallerAuthorizedReferenceLoaderRegistry.class);
        containment = mock(OutboundSecretContainment.class);
        expander = new AttributeReferenceExpander(registry, containment);
    }

    // ---- helpers -------------------------------------------------------------------------------

    private static RequestAttribute resourceRef(AttributeResource kind, UUID... uuids) {
        List<BaseAttributeContentV3<?>> elements = new ArrayList<>();
        for (UUID uuid : uuids) {
            ResourceSimpleContentData ref = new ResourceSimpleContentData(kind);
            ref.setUuid(uuid.toString());
            elements.add(new ResourceObjectContent(null, ref));
        }
        return new RequestAttributeV3(UUID.randomUUID(), "ref", AttributeContentType.RESOURCE, elements);
    }

    private void registerLoader(AttributeResource kind, CallerAuthorizedReferenceLoader loader) {
        when(registry.loaderFor(kind)).thenReturn(loader);
    }

    private static ResourceSimpleContentData blob(AttributeResource kind, UUID uuid) {
        ResourceSimpleContentData blob = new ResourceSimpleContentData(kind);
        blob.setUuid(uuid.toString());
        blob.setName("loaded-" + uuid);
        return blob;
    }

    // ---- AC1: authorized expansion -------------------------------------------------------------

    @Test
    void malformedReferenceUuidFailsAsValidationNotServerError() {
        // A client/connector-supplied malformed reference uuid must surface as AttributeException (4xx), not a
        // raw IllegalArgumentException (unchecked 500).
        ResourceSimpleContentData ref = new ResourceSimpleContentData(AttributeResource.CREDENTIAL);
        ref.setUuid("not-a-uuid");
        List<BaseAttributeContentV3<?>> elements = new ArrayList<>();
        elements.add(new ResourceObjectContent(null, ref));
        RequestAttribute attr = new RequestAttributeV3(UUID.randomUUID(), "ref", AttributeContentType.RESOURCE,
                elements);

        assertThrows(AttributeException.class, () -> expander.expandForCaller(List.of(attr), expandedSecrets));
    }

    @Test
    void expandsCredentialReferenceForAuthorizedCaller() throws Exception {
        UUID uuid = UUID.randomUUID();
        ResourceSimpleContentData blob = blob(AttributeResource.CREDENTIAL, uuid);
        registerLoader(AttributeResource.CREDENTIAL, securedUuid -> {
            assertEquals(uuid, securedUuid.getValue());
            return blob;
        });

        RequestAttribute attr = resourceRef(AttributeResource.CREDENTIAL, uuid);
        expander.expandForCaller(List.of(attr), expandedSecrets);

        ResourceObjectContent element = (ResourceObjectContent) ((List<?>) attr.getContent()).getFirst();
        assertSame(blob, element.getData(), "the bare reference must be replaced by the resolved blob");
    }

    @Test
    void expandsAuthorityEntityLocationReferences() throws Exception {
        for (AttributeResource kind : List
                .of(AttributeResource.AUTHORITY, AttributeResource.ENTITY, AttributeResource.LOCATION)) {
            CallerAuthorizedReferenceLoaderRegistry localRegistry = mock(CallerAuthorizedReferenceLoaderRegistry.class);
            AttributeReferenceExpander localExpander = new AttributeReferenceExpander(localRegistry, containment);
            UUID uuid = UUID.randomUUID();
            ResourceSimpleContentData blob = blob(kind, uuid);
            when(localRegistry.loaderFor(kind)).thenReturn(securedUuid -> blob);

            RequestAttribute attr = resourceRef(kind, uuid);
            localExpander.expandForCaller(List.of(attr), new HashSet<>());

            ResourceObjectContent element = (ResourceObjectContent) ((List<?>) attr.getContent()).getFirst();
            assertSame(blob, element.getData(), kind + " reference must resolve via its guarded loader");
        }
    }

    @Test
    void expandsStoredSecretReferenceAndArmsContainment() throws Exception {
        // A STORED SECRET reference (e.g. an authority's OAuth-client secret) resolves to inline content via the
        // registry's SECRET loader — it is no longer passed through as a bare reference. Expanding a secret also arms
        // the outbound value-echo containment so the resolved secret cannot be reflected back by the connector.
        UUID uuid = UUID.randomUUID();
        ResourceSecretContentData secretBlob = new ResourceSecretContentData();
        registerLoader(AttributeResource.SECRET, securedUuid -> {
            assertEquals(uuid, securedUuid.getValue());
            return secretBlob;
        });

        RequestAttribute attr = resourceRef(AttributeResource.SECRET, uuid);
        expander.expandForCaller(List.of(attr), expandedSecrets);

        ResourceObjectContent element = (ResourceObjectContent) ((List<?>) attr.getContent()).getFirst();
        assertSame(secretBlob, element.getData(), "a stored SECRET reference must resolve to its inline content");
        verify(containment).recordExpandedSecrets(secretBlob, expandedSecrets);
    }

    // ---- AC2: fail-closed ----------------------------------------------------------------------

    @Test
    void failsClosedWhenCallerNotAuthorizedForReferencedObject() {
        UUID uuid = UUID.randomUUID();
        registerLoader(AttributeResource.CREDENTIAL, securedUuid -> {
            throw new AccessDeniedException("denied");
        });

        RequestAttribute attr = resourceRef(AttributeResource.CREDENTIAL, uuid);
        assertThrows(AccessDeniedException.class, () -> expander.expandForCaller(List.of(attr), expandedSecrets),
                "a DETAIL denial must propagate — no swallow, no partial expansion");

        ResourceObjectContent element = (ResourceObjectContent) ((List<?>) attr.getContent()).getFirst();
        assertInstanceOf(ResourceSimpleContentData.class, element.getData());
        assertTrue(((ResourceSimpleContentData) element.getData()).getAttributes() == null,
                "the bare reference must remain unexpanded on denial");
    }

    @Test
    void multiSelectFailsClosedIfAnyElementUnauthorized() {
        UUID allowed = UUID.randomUUID();
        UUID denied = UUID.randomUUID();
        registerLoader(AttributeResource.CREDENTIAL, securedUuid -> {
            if (denied.equals(securedUuid.getValue())) {
                throw new AccessDeniedException("denied");
            }
            return blob(AttributeResource.CREDENTIAL, securedUuid.getValue());
        });

        // order the denied element first so the failure aborts before the allowed one would expand
        RequestAttribute attr = resourceRef(AttributeResource.CREDENTIAL, denied, allowed);
        assertThrows(AccessDeniedException.class, () -> expander.expandForCaller(List.of(attr), expandedSecrets),
                "multi-select must fail the whole call if the caller lacks DETAIL on any element");
    }

    // ---- pass-through, repeats, nesting ---------------------------------------------------------

    @Test
    void leavesAReferenceUntouched_whenItsKindHasNoLoader() throws Exception {
        // given
        var kindWithoutALoader = AttributeResource.CERTIFICATE;
        when(registry.loaderFor(kindWithoutALoader)).thenReturn(null);
        RequestAttribute attr = resourceRef(kindWithoutALoader, UUID.randomUUID());
        ResourceObjectContentData original = firstElement(attr).getData();

        // when
        expander.expandForCaller(List.of(attr), expandedSecrets);

        // then
        assertThat(firstElement(attr).getData()).isSameAs(original);
        verify(containment, never()).recordExpandedSecrets(ArgumentMatchers.any(), ArgumentMatchers.any());
    }

    @Test
    void reusesTheLoadedObject_whenAMultiSelectNamesItTwice() throws Exception {
        // given
        UUID uuid = UUID.randomUUID();
        CallerAuthorizedReferenceLoader loader = mock(CallerAuthorizedReferenceLoader.class);
        when(loader.loadAuthorized(ArgumentMatchers.any()))
                .thenAnswer(call -> blob(AttributeResource.CREDENTIAL, uuid));
        registerLoader(AttributeResource.CREDENTIAL, loader);
        RequestAttribute attr = resourceRef(AttributeResource.CREDENTIAL, uuid, uuid);

        // when
        expander.expandForCaller(List.of(attr), expandedSecrets);

        // then
        List<?> elements = attr.getContent();
        ResourceObjectContentData first = ((ResourceObjectContent) elements.get(0)).getData();
        ResourceObjectContentData second = ((ResourceObjectContent) elements.get(1)).getData();
        assertThat(second).isSameAs(first);
        verify(loader).loadAuthorized(ArgumentMatchers.any());
    }

    @Test
    void loadsANestedSecretThroughTheLending_whenTheAuthorityLendsIt() throws Exception {
        // given
        UUID authorityUuid = UUID.randomUUID();
        UUID secretUuid = UUID.randomUUID();
        ResourceSecretContentData secretContent = new ResourceSecretContentData();
        ReferenceLoader lentLoader = mock(ReferenceLoader.class);
        when(lentLoader.load(AttributeResource.SECRET, secretUuid)).thenReturn(secretContent);
        registerLoader(AttributeResource.AUTHORITY, uuid -> authorityHolding(authorityUuid, secretUuid));
        RequestAttribute attr = resourceRef(AttributeResource.AUTHORITY, authorityUuid);

        // when
        expander.expandForCaller(List.of(attr), expandedSecrets, (kind, uuid) -> lentLoader);

        // then
        ResourceSimpleContentData authority = (ResourceSimpleContentData) firstElement(attr).getData();
        List<?> oauthClient = authority.getAttributes().getFirst().getContent();
        assertThat(((ResourceObjectContent) oauthClient.getFirst()).getData()).isSameAs(secretContent);
        verify(registry, never()).loaderFor(AttributeResource.SECRET);
        verify(containment).recordExpandedSecrets(secretContent, expandedSecrets);
    }

    @Test
    void leavesANestedSecretAReference_whenNothingIsLent() throws Exception {
        // given
        UUID authorityUuid = UUID.randomUUID();
        registerLoader(AttributeResource.AUTHORITY, uuid -> authorityHolding(authorityUuid, UUID.randomUUID()));
        RequestAttribute attr = resourceRef(AttributeResource.AUTHORITY, authorityUuid);

        // when
        expander.expandForCaller(List.of(attr), expandedSecrets);

        // then
        ResourceSimpleContentData authority = (ResourceSimpleContentData) firstElement(attr).getData();
        List<?> oauthClient = authority.getAttributes().getFirst().getContent();
        assertThat(((ResourceObjectContent) oauthClient.getFirst()).getData())
                .isInstanceOfSatisfying(ResourceSecretContentData.class,
                        secret -> assertThat(secret.getContent()).isNull());
        verify(registry, never()).loaderFor(AttributeResource.SECRET);
    }

    // ── Helpers ───────────────────────────────────────────────────────────────

    private static ResourceObjectContent firstElement(RequestAttribute attribute) {
        List<?> elements = attribute.getContent();
        return (ResourceObjectContent) elements.getFirst();
    }

    /** An authority whose one attribute is its OAuth client: a bare reference to a secret, as stored. */
    private static ResourceSimpleContentData authorityHolding(UUID authorityUuid, UUID secretUuid) {
        List<BaseAttributeContentV3<?>> oauthClient = new ArrayList<>();
        oauthClient
                .add(new ResourceObjectContent("oauth-client",
                        new ResourceSecretContentData(secretUuid.toString(), "oauth-client", null)));
        ResourceSimpleContentData authority = blob(AttributeResource.AUTHORITY, authorityUuid);
        authority
                .setAttributes(new ArrayList<>(List
                        .of(new ResponseAttributeV3(oauthClient, UUID.randomUUID(), "oauthClient", "OAuth client",
                                AttributeType.DATA, AttributeContentType.RESOURCE, AttributeVersion.V3))));
        return authority;
    }
}
