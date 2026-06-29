package com.otilm.core.attribute.engine;

import com.otilm.api.exception.AttributeException;
import com.otilm.api.model.client.attribute.RequestAttribute;
import com.otilm.api.model.client.attribute.RequestAttributeV3;
import com.otilm.api.model.common.attribute.common.content.AttributeContentType;
import com.otilm.api.model.common.attribute.v3.content.BaseAttributeContentV3;
import com.otilm.api.model.common.attribute.v3.content.ResourceObjectContent;
import com.otilm.api.model.common.attribute.v3.content.data.ResourceObjectContentData;
import com.otilm.api.model.common.attribute.v3.content.data.ResourceSimpleContentData;
import com.otilm.api.model.core.auth.AttributeResource;
import com.otilm.core.security.authz.SecuredUUID;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentMatchers;
import org.springframework.security.access.AccessDeniedException;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.UUID;

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
 * Security-heavy unit tests for the callback-mode reference expander. The DETAIL gate itself is exercised
 * through the registry's loader (mocked to throw {@link AccessDeniedException} for "denied" objects), so these
 * tests assert the expander's fail-closed, cycle, depth, multi-select and pass-through behaviour without a Spring
 * context. The real per-object aspect is covered by the ArchUnit fence + the guarded loaders' own annotations.
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
        RequestAttribute attr = new RequestAttributeV3(UUID.randomUUID(), "ref", AttributeContentType.RESOURCE, elements);

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
        for (AttributeResource kind : List.of(AttributeResource.AUTHORITY, AttributeResource.ENTITY, AttributeResource.LOCATION)) {
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

    // ---- AC2: fail-closed ----------------------------------------------------------------------

    @Test
    void failsClosedWhenCallerNotAuthorizedForReferencedObject() {
        UUID uuid = UUID.randomUUID();
        registerLoader(AttributeResource.CREDENTIAL, securedUuid -> {
            throw new AccessDeniedException("denied");
        });

        RequestAttribute attr = resourceRef(AttributeResource.CREDENTIAL, uuid);
        assertThrows(AccessDeniedException.class,
                () -> expander.expandForCaller(List.of(attr), expandedSecrets),
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
        assertThrows(AccessDeniedException.class,
                () -> expander.expandForCaller(List.of(attr), expandedSecrets),
                "multi-select must fail the whole call if the caller lacks DETAIL on any element");
    }

    // ---- AC3: cycle / depth --------------------------------------------------------------------

    @Test
    void passesThroughKindsWithoutAConnectorConsumableBlob() throws Exception {
        UUID uuid = UUID.randomUUID();
        when(registry.loaderFor(AttributeResource.SECRET)).thenReturn(null);

        RequestAttribute attr = resourceRef(AttributeResource.SECRET, uuid);
        ResourceObjectContent before = (ResourceObjectContent) ((List<?>) attr.getContent()).getFirst();
        ResourceObjectContentData original = before.getData();

        expander.expandForCaller(List.of(attr), expandedSecrets);

        assertSame(original, before.getData(), "a pass-through kind (SECRET) must be left untouched");
        verify(containment, never()).recordExpandedSecrets(ArgumentMatchers.any(), ArgumentMatchers.any());
    }

    // Note: the depth-cap and cross-frame cycle guard are not exercised end-to-end because nested-blob resolution
    // is not wired (attributesOf returns empty — single-level expansion only). Those kernels are unit-tested as
    // pure functions in ReferenceTraversalTest; an end-to-end depth/cycle test lands with the op-path follow-up
    // that makes attributesOf live. The tautological inline-throw test was removed (it asserted nothing real).

    @Test
    void multiSelectSiblingDedupByVisitedSet() throws Exception {
        UUID uuid = UUID.randomUUID();
        ResourceSimpleContentData blob = blob(AttributeResource.CREDENTIAL, uuid);
        registerLoader(AttributeResource.CREDENTIAL, securedUuid -> blob);

        // same uuid referenced twice in one multi-select: the second sighting is skipped by the visited set, no re-load
        RequestAttribute attr = resourceRef(AttributeResource.CREDENTIAL, uuid, uuid);
        expander.expandForCaller(List.of(attr), expandedSecrets);

        ResourceObjectContent first = (ResourceObjectContent) ((List<?>) attr.getContent()).get(0);
        ResourceObjectContent second = (ResourceObjectContent) ((List<?>) attr.getContent()).get(1);
        assertSame(blob, first.getData());
        // second element was not expanded (already visited) — remains the bare reference
        assertInstanceOf(ResourceSimpleContentData.class, second.getData());
        assertTrue(((ResourceSimpleContentData) second.getData()).getAttributes() == null);
    }
}
