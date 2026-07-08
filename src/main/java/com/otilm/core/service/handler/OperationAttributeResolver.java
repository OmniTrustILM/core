package com.otilm.core.service.handler;

import com.otilm.api.exception.AttributeException;
import com.otilm.api.exception.ConnectorException;
import com.otilm.api.exception.NotFoundException;
import com.otilm.api.exception.ValidationException;
import com.otilm.api.model.client.attribute.RequestAttribute;
import com.otilm.api.model.common.attribute.common.content.AttributeContentType;
import com.otilm.core.attribute.engine.ConnectorRequestAttributesBuilder;
import com.otilm.core.util.AuthHelper;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import java.util.List;
import java.util.UUID;

/**
 * Resolves an entity's own <strong>infrastructure</strong> references (CREDENTIAL + RESOURCE incl. SECRET) into
 * inline content for an operation-path connector request — the single home for "system-mode operation-path
 * attribute resolution" that every Attributes-v2 operation adapter can delegate to.
 * <p>
 * <b>Authorization:</b> the dereference runs under the {@code attribute-content-resolver} system identity (via
 * {@link AuthHelper#runAsSystem}), authorized at the operation level rather than per acting caller — so it works for
 * operators, low-privilege protocol robots (ACME/SCEP/CMP), and the principal-less async status-poll thread alike.
 * <p>
 * <b>Scope:</b> the elevation covers the dereference only; {@code runAsSystem} restores the caller's context, so the
 * rest of the operation runs as the caller.
 * <p>
 * <b>Placement:</b> this lives outside {@code com.otilm.core.attribute.engine} because the reference expander's
 * ArchUnit fence forbids that package from touching {@link AuthHelper}; the callback path stays per-object
 * caller-authorized and only this operation path elevates.
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

    public List<RequestAttribute> resolveForConnectorRequestAsSystem(UUID connectorUuid, List<RequestAttribute> stored)
            throws ConnectorException {
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
                return connectorRequestAttributesBuilder.dereferenceForConnectorRequest(connectorUuid, stored);
            } catch (AttributeException | NotFoundException | ValidationException e) {
                // A stored reference may be unresolvable, or point at a disabled/invalid-state secret or vault profile
                // (unchecked ValidationException). Surface all through the declared ConnectorException contract so the
                // operation fails cleanly instead of escaping as a raw RuntimeException.
                throw new ConnectorException("Unable to resolve stored attribute references for connector request (connector " + connectorUuid + ")", e);
            }
        });
    }

    private static boolean isInfrastructureReference(RequestAttribute attribute) {
        AttributeContentType type = attribute.getContentType();
        return type == AttributeContentType.CREDENTIAL || type == AttributeContentType.RESOURCE;
    }
}
