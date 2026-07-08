package com.otilm.core.attribute.engine;

import com.otilm.api.exception.AttributeException;
import com.otilm.api.exception.ConnectorException;
import com.otilm.api.exception.NotFoundException;
import com.otilm.api.model.client.attribute.RequestAttribute;
import com.otilm.api.model.common.attribute.v3.content.BaseAttributeContentV3;
import com.otilm.api.model.common.attribute.v3.content.ResourceObjectContent;
import com.otilm.api.model.common.attribute.v3.content.data.ResourceObjectContentData;
import com.otilm.api.model.core.auth.AttributeResource;
import com.otilm.core.security.authz.SecuredUUID;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

import java.util.ArrayList;
import java.util.List;
import java.util.Set;
import java.util.UUID;

/**
 * Net-new shared facility (#1624): expands RESOURCE references inside a {@code List<RequestAttribute>} into the
 * referenced object's full connector-consumable attribute blob, so a stateless NG connector can authenticate
 * upstream without holding the credential material itself.
 *
 * <h2>Callback mode — the only mode implemented here</h2>
 * {@link #expandForCaller(List, Set)} authorizes the <em>ambient calling user</em> per referenced object through the
 * resource's object-scoped guarded loader (a {@link SecuredUUID} the auth aspect resolves the concrete object from;
 * the per-kind gate is defined by {@link CallerAuthorizedReferenceLoaderRegistry}). It <strong>fails closed</strong>:
 * any {@code AccessDeniedException} from that gate propagates and aborts the whole expansion — no partial blob is
 * emitted, and multi-select selecting one unauthorized element among authorized ones fails the entire call.
 * <p>
 * The aspect reads the ambient Spring {@code SecurityContext}; there is no API to pass a context in, so there is
 * deliberately no {@code SecurityContext} parameter, and this class performs <strong>no</strong>
 * {@code setAuthentication} / principal swap of any kind (invariant: the expander never swaps the ambient
 * principal — asserted by {@code AttributeReferenceExpanderITest.expanderDoesNotMutateAmbientPrincipal}).
 * <p>
 * <strong>Single-level only today.</strong> Only the references directly present in the passed attribute list
 * are resolved (depth 0). Resolving references nested <em>inside</em> an already-loaded blob (depth 1+) is not
 * wired — {@link #attributesOf} returns empty, so the recursion below is a no-op and the depth/cycle machinery
 * is inactive at runtime. Nested resolution is future work (see below); operation mode does not run through this expander.
 *
 * <h2>The fence</h2>
 * Callback mode resolves <strong>exclusively</strong> through {@link CallerAuthorizedReferenceLoader} —
 * the per-object {@code SecuredUUID}+DETAIL loaders. It must <strong>never</strong> reach the unguarded
 * by-UUID primitives ({@code CredentialServiceImpl.getCredentialEntity}/{@code findByUuid},
 * {@code CredentialService.loadFullCredentialData(List)}, {@code ResourceService.loadResourceObjectContentData(List)},
 * {@code ConnectorRequestAttributesBuilder}). Those primitives are public and pervasively reachable, so a
 * package-private fence is impossible; the boundary is carried by a type-level ArchUnit
 * reachability test ({@code AttributeReferenceExpanderFenceArchTest}). That test is the load-bearing fence.
 *
 * <h2>Operation mode lives outside this class — by design</h2>
 * The v3 operation path (issue/renew/revoke/register, status poll/cancel) does <strong>not</strong> run through
 * this fenced callback expander. {@code OperationAttributeResolver} (from {@code AuthorityProviderV3Adapter})
 * resolves an authority's own infrastructure references there by elevating to the platform's
 * attribute-content-resolver system identity for the dereference only — authorized at the operation level, not per
 * acting caller. The ArchUnit
 * fence forbids this package from depending on {@code AuthHelper}, so the caller-authorized (callback) mode here can
 * never elevate; the two modes stay separated.
 */
@Component
public class AttributeReferenceExpander {

    private static final Logger logger = LoggerFactory.getLogger(AttributeReferenceExpander.class);

    /**
     * Max reference-chain depth for the (not-yet-active) nested-blob recursion. Today {@link #attributesOf}
     * returns empty, so expansion is single-level only and this cap is never reached at runtime; it and the
     * cross-frame cycle guard are kernel-tested ({@link ReferenceTraversal}) scaffolding that becomes live only if a
     * future nested-resolution change activates {@link #attributesOf}. Overflow throws, never silently truncates.
     */
    static final int MAX_DEPTH = 3;

    private final CallerAuthorizedReferenceLoaderRegistry callerRegistry;
    private final OutboundSecretContainment outboundContainment;

    public AttributeReferenceExpander(CallerAuthorizedReferenceLoaderRegistry callerRegistry,
                                      OutboundSecretContainment outboundContainment) {
        this.callerRegistry = callerRegistry;
        this.outboundContainment = outboundContainment;
    }

    /**
     * Callback mode: expand every RESOURCE reference, authorizing the ambient calling user per object via the
     * resource's {@code SecuredUUID}+DETAIL guarded loader. Fail-closed; records the secret-typed values it
     * expanded into {@code expandedSecrets} for the outbound containment check on the connector's response.
     *
     * @param attributes      the request attributes to expand in place
     * @param expandedSecrets out-param collecting secret values this call materialized (for outbound containment)
     */
    public List<RequestAttribute> expandForCaller(List<RequestAttribute> attributes, Set<String> expandedSecrets)
            throws NotFoundException, AttributeException, ConnectorException {
        expand(attributes, new java.util.HashSet<>(), 0, expandedSecrets);
        return attributes;
    }

    private void expand(List<RequestAttribute> attributes, Set<String> visited, int depth, Set<String> expandedSecrets)
            throws NotFoundException, AttributeException, ConnectorException {
        if (attributes == null || attributes.isEmpty()) {
            return;
        }
        for (RequestAttribute attribute : attributes) {
            if (!isResourceReference(attribute)) {
                continue;
            }
            // multi-select: one content element per selected object; all share the call's visited-set + depth.
            for (BaseAttributeContentV3<?> element : resourceElements(attribute)) {
                expandElement((ResourceObjectContent) element, visited, depth, expandedSecrets);
            }
        }
    }

    private void expandElement(ResourceObjectContent element, Set<String> visited, int depth, Set<String> expandedSecrets)
            throws NotFoundException, AttributeException, ConnectorException {
        ResourceObjectContentData ref = element.getData();
        if (ref == null || ref.getResource() == null || ref.getUuid() == null) {
            return;
        }
        AttributeResource kind = ref.getResource();
        final UUID uuid;
        try {
            uuid = UUID.fromString(ref.getUuid());
        } catch (IllegalArgumentException e) {
            // The reference uuid is client/connector-supplied; a malformed value is a validation error (4xx),
            // not an unchecked 500. Echoing the bad value is safe — it is the caller's own input.
            throw new AttributeException("Malformed RESOURCE reference UUID: " + ref.getUuid());
        }

        if (!ReferenceTraversal.shouldDescend(kind, uuid, visited)) {
            return; // already expanded on this call (cycle guard)
        }
        if (ReferenceTraversal.exceedsDepth(depth, MAX_DEPTH)) {
            throw ReferenceExpansionException.depthExceeded(kind, uuid, MAX_DEPTH);
        }

        CallerAuthorizedReferenceLoader loader = callerRegistry.loaderFor(kind);
        if (loader == null) {
            // No connector-consumable blob for this kind (e.g. plain reference): pass through unchanged.
            return;
        }

        // Per-object DETAIL gate + blob load. Any AccessDeniedException from the guarded loader propagates
        // (fail-closed): we deliberately do NOT catch it, so no partial expansion escapes.
        ResourceObjectContentData blob = loader.loadAuthorized(SecuredUUID.fromUUID(uuid));
        element.setData(blob);
        outboundContainment.recordExpandedSecrets(blob, expandedSecrets);

        // Wiring point for nested resolution: today attributesOf(blob) returns empty (single-level only), so this
        // is a no-op. A future nested-resolution change makes it live; the depth/cycle guards above protect it then.
        expand(attributesOf(blob), visited, depth + 1, expandedSecrets);
    }

    private static boolean isResourceReference(RequestAttribute attribute) {
        Object content = attribute.getContent();
        return content instanceof List<?> list
                && !list.isEmpty()
                && list.getFirst() instanceof ResourceObjectContent;
    }

    @SuppressWarnings("unchecked")
    private static List<BaseAttributeContentV3<?>> resourceElements(RequestAttribute attribute) {
        List<BaseAttributeContentV3<?>> elements = new ArrayList<>();
        for (Object o : (List<Object>) attribute.getContent()) {
            if (o instanceof ResourceObjectContent roc) {
                elements.add(roc);
            }
        }
        return elements;
    }

    /**
     * The attributes nested inside an already-loaded blob, as the {@code List<RequestAttribute>} the recursion
     * would consume. <strong>Returns empty unconditionally today</strong>: nested-blob resolution is not yet
     * wired, so expansion is single-level. A loaded blob's nested attributes are {@code ResponseAttribute}, not
     * {@code RequestAttribute}, and are not re-resolvable in place; translating them into recursion input is future
     * work. Until then a reference nested inside a loaded blob stays a bare reference.
     */
    private static List<RequestAttribute> attributesOf(ResourceObjectContentData blob) {
        // Nested-blob resolution is future work (single-level expansion only today): always empty. Real extraction
        // lands with a future nested-resolution change; see the Javadoc above.
        return List.of();
    }

    // Operation mode is deliberately not implemented here (see class Javadoc); only nested-blob resolution via
    // attributesOf(), above, remains deferred.
}
