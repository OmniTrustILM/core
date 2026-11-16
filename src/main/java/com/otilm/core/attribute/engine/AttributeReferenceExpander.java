package com.otilm.core.attribute.engine;

import com.otilm.api.exception.AttributeException;
import com.otilm.api.exception.ConnectorException;
import com.otilm.api.exception.NotFoundException;
import com.otilm.api.model.client.attribute.RequestAttribute;
import com.otilm.api.model.common.attribute.v3.content.ResourceObjectContent;
import com.otilm.api.model.common.attribute.v3.content.data.ResourceObjectContentData;
import com.otilm.api.model.core.auth.AttributeResource;
import com.otilm.core.security.authz.SecuredUUID;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.UUID;
import org.springframework.stereotype.Component;

/**
 * Expands RESOURCE references inside a {@code List<RequestAttribute>} into the referenced objects' connector-consumable
 * content, so a stateless connector can authenticate upstream without holding the credential material itself.
 *
 * <h2>Callback mode</h2> {@link #expandForCaller(List, Set)} authorizes the <em>ambient calling user</em> on every
 * object the attributes refer to, through the resource's object-scoped guarded loader (a {@link SecuredUUID} the auth
 * aspect resolves the concrete object from; the per-kind gate is defined by
 * {@link CallerAuthorizedReferenceLoaderRegistry}). It <strong>fails closed</strong>: a denial on any object aborts the
 * whole expansion, so no partial request escapes, and multi-select selecting one unauthorized element among authorized
 * ones fails the entire call.
 * <p>
 * The references inside those objects are resolved only when the {@link ReferenceLending} passed to
 * {@link #expandForCaller(List, Set, ReferenceLending)} lends them; it comes from outside this package because lending
 * resolves as the system. Every secret either loader materializes is recorded for the outbound containment check.
 * <p>
 * The aspect reads the ambient Spring {@code SecurityContext}; there is no API to pass a context in, so there is
 * deliberately no {@code SecurityContext} parameter, and this class performs <strong>no</strong>
 * {@code setAuthentication} / principal swap of any kind (asserted by
 * {@code AttributeReferenceExpanderITest.expanderDoesNotMutateAmbientPrincipal}).
 *
 * <h2>The fence</h2> The caller's own references resolve <strong>exclusively</strong> through
 * {@link CallerAuthorizedReferenceLoader} — the per-object {@code SecuredUUID} loaders. This class must
 * <strong>never</strong> reach the unguarded by-UUID primitives ({@code CredentialServiceImpl.getCredentialEntity}/
 * {@code findByUuid}, {@code CredentialInternalService.loadFullCredentialData(List)},
 * {@code ResourceInternalService.loadResourceObjectContentData(List)},
 * {@code ResourceInternalService.loadReferencedObjectContent}, {@code ConnectorRequestAttributesBuilder}). Those
 * primitives are public and pervasively reachable, so a package-private fence is impossible; the boundary is carried by
 * a type-level ArchUnit reachability test ({@code AttributeReferenceExpanderFenceArchTest}).
 *
 * <h2>System mode lives outside this class — by design</h2> The v3 operation path and Discovery v2 runs resolve through
 * {@code OperationAttributeResolver}, which elevates to the platform's attribute-content-resolver system identity. The
 * ArchUnit fence forbids this package from depending on {@code AuthHelper}, so this class can never elevate by itself.
 */
@Component
public class AttributeReferenceExpander {

    private final CallerAuthorizedReferenceLoaderRegistry callerRegistry;
    private final OutboundSecretContainment outboundContainment;

    public AttributeReferenceExpander(CallerAuthorizedReferenceLoaderRegistry callerRegistry,
            OutboundSecretContainment outboundContainment) {
        this.callerRegistry = callerRegistry;
        this.outboundContainment = outboundContainment;
    }

    /**
     * Expands every RESOURCE reference, authorizing the ambient calling user on each object, and leaves the references
     * inside those objects as they are. Fail-closed; records the secret-typed values it expanded into
     * {@code expandedSecrets} for the outbound containment check on the connector's response.
     *
     * @param attributes the request attributes to expand in place
     * @param expandedSecrets out-param collecting secret values this call materialized (for outbound containment)
     */
    public List<RequestAttribute> expandForCaller(List<RequestAttribute> attributes, Set<String> expandedSecrets)
            throws NotFoundException, AttributeException, ConnectorException {
        return expandForCaller(attributes, expandedSecrets, ReferenceLending.NOTHING);
    }

    /**
     * As {@link #expandForCaller(List, Set)}, and also resolves the references inside each object the lending lends.
     *
     * @param lending decides which objects lend their own references, and the loader they are resolved with
     */
    public List<RequestAttribute> expandForCaller(List<RequestAttribute> attributes, Set<String> expandedSecrets,
            ReferenceLending lending) throws NotFoundException, AttributeException, ConnectorException {
        if (attributes == null) {
            return null;
        }
        ReferenceTraversal traversal = new ReferenceTraversal(
                (kind, uuid) -> loadForCaller(kind, uuid, expandedSecrets), recorded(lending, expandedSecrets));
        for (RequestAttribute attribute : attributes) {
            traversal.resolve(attribute.getName(), attribute.getContent());
        }
        return attributes;
    }

    /**
     * Checks, through the guarded loader {@link #expandForCaller(List, Set)} uses, that the calling user may see the
     * object a reference names. The reference is left as it is; a kind sent bare needs no check.
     */
    public void requireCallerMayLoad(String attributeName, ResourceObjectContent reference)
            throws NotFoundException, AttributeException, ConnectorException {
        ResourceObjectContent probe = new ResourceObjectContent(reference.getReference(), reference.getData());
        new ReferenceTraversal((kind, uuid) -> loadForCaller(kind, uuid, new HashSet<>()), ReferenceLending.NOTHING)
                .resolve(attributeName, List.of(probe));
    }

    private ResourceObjectContentData loadForCaller(AttributeResource kind, UUID uuid, Set<String> expandedSecrets)
            throws NotFoundException, AttributeException, ConnectorException {
        CallerAuthorizedReferenceLoader loader = callerRegistry.loaderFor(kind);
        if (loader == null) {
            return null;
        }
        ResourceObjectContentData content = loader.loadAuthorized(SecuredUUID.fromUUID(uuid));
        outboundContainment.recordExpandedSecrets(content, expandedSecrets);
        return content;
    }

    /** The lending, with every secret its loaders materialize recorded for the outbound containment check. */
    private ReferenceLending recorded(ReferenceLending lending, Set<String> expandedSecrets) {
        return new ReferenceLending() {
            @Override
            public ReferenceLoader insideOf(AttributeResource kind, UUID uuid) {
                ReferenceLoader lent = lending.insideOf(kind, uuid);
                if (lent == null) {
                    return null;
                }
                return (nestedKind, nestedUuid) -> {
                    ResourceObjectContentData content = lent.load(nestedKind, nestedUuid);
                    outboundContainment.recordExpandedSecrets(content, expandedSecrets);
                    return content;
                };
            }

            @Override
            public boolean belongsToAnotherConnector(AttributeResource kind, UUID uuid) {
                return lending.belongsToAnotherConnector(kind, uuid);
            }
        };
    }
}
