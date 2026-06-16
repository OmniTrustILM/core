package com.otilm.core.service.handler.authority;

import com.otilm.api.clients.ApiClientConnectorInfo;
import com.otilm.api.exception.ConnectorException;
import com.otilm.api.exception.NotFoundException;
import com.otilm.api.model.client.attribute.RequestAttribute;
import com.otilm.api.model.common.attribute.common.MetadataAttribute;
import com.otilm.api.model.core.auth.Resource;
import com.otilm.core.attribute.engine.AttributeEngine;
import com.otilm.core.attribute.engine.records.ObjectAttributeContentInfo;
import com.otilm.core.client.ConnectorApiFactory;
import com.otilm.core.dao.entity.AuthorityInstanceReference;
import com.otilm.core.dao.entity.Certificate;
import com.otilm.core.dao.entity.RaProfile;
import com.otilm.core.service.v2.ConnectorService;

import java.util.List;

/**
 * Shared base for the version-specific authority provider adapters. Holds the collaborators
 * and the version-agnostic helpers that were previously copy-pasted between
 * {@link AuthorityProviderV2Adapter} and {@link AuthorityProviderV3Adapter}: connector
 * resolution, RA-profile attribute loading, and metadata-bag loading.
 *
 * <p>Version-specific behavior (request building, the per-version HTTP-status response
 * matrices, issue-attribute operation tagging) stays in the concrete subclasses — those
 * genuinely differ per wire contract and must not be merged.</p>
 */
public abstract class AbstractAuthorityProviderAdapter implements AuthorityProviderAdapter {

    protected final ConnectorService connectorService;
    protected final ConnectorApiFactory connectorApiFactory;
    protected final AttributeEngine attributeEngine;

    protected AbstractAuthorityProviderAdapter(ConnectorService connectorService,
                                               ConnectorApiFactory connectorApiFactory,
                                               AttributeEngine attributeEngine) {
        this.connectorService = connectorService;
        this.connectorApiFactory = connectorApiFactory;
        this.attributeEngine = attributeEngine;
    }

    protected ApiClientConnectorInfo connectorForApiClient(AuthorityInstanceReference authority) throws ConnectorException {
        try {
            return connectorService.getConnectorForApiClient(authority.getConnectorUuid());
        } catch (NotFoundException e) {
            throw new ConnectorException("Connector not found for authority instance: " + authority.getAuthorityInstanceUuid(), e);
        }
    }

    protected List<RequestAttribute> raProfileAttributesFor(RaProfile raProfile, AuthorityInstanceReference authority) {
        return attributeEngine.getRequestObjectDataAttributesContent(
                ObjectAttributeContentInfo.builder(Resource.RA_PROFILE, raProfile.getUuid())
                        .connector(authority.getConnectorUuid())
                        .build());
    }

    /**
     * Loads the stored metadata bag for a certificate — the connector-owned opaque attributes
     * captured on a prior issue/renew/register and replayed verbatim on subsequent operations
     * (the unified meta model). Empty when the certificate has no stored meta.
     */
    protected List<MetadataAttribute> loadMeta(Certificate cert, AuthorityInstanceReference authority) {
        return attributeEngine.getMetadataAttributesDefinitionContent(
                ObjectAttributeContentInfo.builder(Resource.CERTIFICATE, cert.getUuid())
                        .connector(authority.getConnectorUuid())
                        .build());
    }
}
