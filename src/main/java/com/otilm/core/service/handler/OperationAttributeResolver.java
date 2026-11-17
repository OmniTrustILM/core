package com.otilm.core.service.handler;

import com.otilm.api.exception.AttributeException;
import com.otilm.api.exception.ConnectorException;
import com.otilm.api.exception.NotFoundException;
import com.otilm.api.exception.ValidationException;
import com.otilm.api.model.client.attribute.RequestAttribute;
import com.otilm.api.model.common.attribute.common.content.AttributeContentType;
import com.otilm.core.attribute.engine.ConnectorRequestAttributesBuilder;
import com.otilm.core.attribute.engine.MissingReferenceException;
import com.otilm.core.exception.DanglingReferenceException;
import com.otilm.core.util.AuthHelper;
import java.util.List;
import java.util.UUID;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

/**
 * Resolves an entity's own <strong>infrastructure</strong> references (CREDENTIAL + RESOURCE incl. SECRET) into inline
 * content for an operation-path connector request — the single home for "system-mode operation-path attribute
 * resolution" that every Attributes-v2 operation adapter can delegate to.
 * <p>
 * <b>Authorization:</b> the dereference runs under the {@code attribute-content-resolver} system identity (via
 * {@link AuthHelper#runAsSystem}), authorized at the operation level rather than per acting caller — so it works for
 * operators, low-privilege protocol robots (ACME/SCEP/CMP/EST), and the principal-less async status-poll thread alike.
 * <p>
 * <b>Scope:</b> the elevation covers the dereference only; {@code runAsSystem} restores the caller's context, so the
 * rest of the operation runs as the caller.
 * <p>
 * <b>Placement:</b> this lives outside {@code com.otilm.core.attribute.engine} because the reference expander's
 * ArchUnit fence forbids that package from touching {@link AuthHelper}. The callback path authorizes the caller on
 * every object a request names; besides this class only {@link OwnConnectorReferenceLending} elevates, for what those
 * objects lend.
 * <p>
 * <b>Nesting:</b> {@link #resolveForConnectorRequestAsSystem} resolves one level.
 * {@link #resolveWithNestedReferencesAsSystem} also resolves the references inside each named object that belongs to
 * the request's connector (see {@link com.otilm.core.attribute.engine.ReferenceLending}), down to the traversal's depth
 * cap. It is only for attributes whose creation checked the creator on every lending object they name, as a Discovery
 * v2 run's creation does.
 * <p>
 * <b>Failures:</b> an unresolvable stored reference surfaces as {@link ConnectorException}, the one checked type the
 * elevated body may declare. A disabled or invalid-state secret or vault profile, a reference whose object is gone or
 * belongs to another connector, or references nested deeper than the cap surface as a {@link ValidationException}
 * instead: it names the object the operator has to fix and maps to 422, which wrapping would turn into a 500 carrying
 * no message. A caller that cannot recover from an unchecked exception has to wrap it itself;
 * {@code AuthorityProviderV3Adapter.pollStatus} does, because the poll listener recovers only from
 * {@link ConnectorException}.
 */
@Component
public class OperationAttributeResolver {

    private final AuthHelper authHelper;
    private final ConnectorRequestAttributesBuilder connectorRequestAttributesBuilder;

    @Autowired
    public OperationAttributeResolver(AuthHelper authHelper,
            ConnectorRequestAttributesBuilder connectorRequestAttributesBuilder) {
        this.authHelper = authHelper;
        this.connectorRequestAttributesBuilder = connectorRequestAttributesBuilder;
    }

    /** The stored attributes with their own references resolved, one level deep. */
    public List<RequestAttribute> resolveForConnectorRequestAsSystem(UUID connectorUuid, List<RequestAttribute> stored)
            throws ConnectorException {
        return resolveAsSystem(connectorUuid, stored,
                connectorRequestAttributesBuilder::dereferenceForConnectorRequest);
    }

    /**
     * The stored attributes with their references resolved, and the references inside the objects those name. See the
     * class Javadoc for which attributes may use it.
     */
    public List<RequestAttribute> resolveWithNestedReferencesAsSystem(UUID connectorUuid, List<RequestAttribute> stored)
            throws ConnectorException {
        return resolveAsSystem(connectorUuid, stored,
                connectorRequestAttributesBuilder::dereferenceWithNestedReferencesForConnectorRequest);
    }

    /** One of the builder's dereferences, which may fail with the checked types the elevated body maps. */
    @FunctionalInterface
    private interface Dereference {
        List<RequestAttribute> apply(UUID connectorUuid, List<RequestAttribute> stored)
                throws AttributeException, NotFoundException, ConnectorException;
    }

    private List<RequestAttribute> resolveAsSystem(UUID connectorUuid, List<RequestAttribute> stored,
            Dereference dereference) throws ConnectorException {
        if (stored == null) {
            return List.of();
        }
        if (stored.stream().noneMatch(OperationAttributeResolver::isInfrastructureReference)) {
            // No infrastructure reference to resolve: skip the system-identity elevation (and its auth-service
            // round-trip) and hand the connector the stored attributes unchanged, as it receives them for a
            // reference-free authority.
            return stored;
        }
        return authHelper.runAsSystem(AuthHelper.ATTRIBUTE_CONTENT_RESOLVER_USERNAME, () -> {
            try {
                return dereference.apply(connectorUuid, stored);
            } catch (DanglingReferenceException e) {
                throw new MissingReferenceException(e.getMessage());
            } catch (AttributeException | NotFoundException e) {
                // ValidationException is deliberately not caught here — see the class Javadoc's Failures paragraph.
                throw new ConnectorException(
                        "Unable to resolve stored attribute references for connector request (connector "
                                + connectorUuid + ")",
                        e);
            }
        });
    }

    private static boolean isInfrastructureReference(RequestAttribute attribute) {
        AttributeContentType type = attribute.getContentType();
        return type == AttributeContentType.CREDENTIAL || type == AttributeContentType.RESOURCE;
    }
}
