package com.otilm.core.service.handler;

import com.otilm.api.exception.AttributeException;
import com.otilm.api.exception.ConnectorException;
import com.otilm.api.exception.NotFoundException;
import com.otilm.api.model.common.attribute.v3.content.data.ResourceObjectContentData;
import com.otilm.api.model.core.auth.AttributeResource;
import com.otilm.core.attribute.engine.ReferenceLending;
import com.otilm.core.service.ResourceInternalService;
import com.otilm.core.util.AuthHelper;
import java.util.UUID;
import org.springframework.stereotype.Component;

/**
 * Lends a connector the references inside the objects that belong to it, resolved under the
 * {@code attribute-content-resolver} system identity, for a form callback the caller makes.
 * <p>
 * The caller is still checked on every object the request refers to. What such an object refers to in turn, such as an
 * authority's OAuth client secret, was attached to the object when it was created, for its own connector; that
 * connector receives it for every operation of the object anyway, so resolving it for the same connector creates no new
 * holder and asks nothing more of the caller. The references inside an object of another connector stay references.
 * <p>
 * This lives outside {@code com.otilm.core.attribute.engine} because that package must not elevate; the expander
 * receives the lending from here.
 */
@Component
public class OwnConnectorReferenceLending {

    private final AuthHelper authHelper;
    private final ResourceInternalService resourceService;

    public OwnConnectorReferenceLending(AuthHelper authHelper, ResourceInternalService resourceService) {
        this.authHelper = authHelper;
        this.resourceService = resourceService;
    }

    /** The lending for a request to the connector. */
    public ReferenceLending forConnector(UUID connectorUuid) {
        return (kind, uuid) -> resourceService.findOwningConnector(kind, uuid).filter(connectorUuid::equals).isPresent()
                ? this::loadAsSystem
                : null;
    }

    private ResourceObjectContentData loadAsSystem(AttributeResource kind, UUID uuid)
            throws NotFoundException, AttributeException, ConnectorException {
        try {
            return authHelper
                    .runAsSystem(AuthHelper.ATTRIBUTE_CONTENT_RESOLVER_USERNAME,
                            () -> resourceService.loadReferencedObjectContent(kind, uuid));
        } catch (NotFoundException | AttributeException | ConnectorException | RuntimeException e) {
            throw e;
        } catch (Exception e) {
            throw new IllegalStateException("Unexpected failure resolving a referenced object", e);
        }
    }
}
