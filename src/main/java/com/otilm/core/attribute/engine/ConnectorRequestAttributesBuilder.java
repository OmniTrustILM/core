package com.otilm.core.attribute.engine;

import com.otilm.api.exception.AttributeException;
import com.otilm.api.exception.ConnectorException;
import com.otilm.api.exception.NotFoundException;
import com.otilm.api.model.client.attribute.RequestAttribute;
import com.otilm.api.model.common.attribute.common.BaseAttribute;
import com.otilm.api.model.common.attribute.common.DataAttribute;
import com.otilm.core.service.CredentialInternalService;
import com.otilm.core.service.ResourceInternalService;
import com.otilm.core.util.AttributeDefinitionUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import java.util.List;
import java.util.UUID;

@Component
public class ConnectorRequestAttributesBuilder {

    private AttributeEngine attributeEngine;
    private ResourceInternalService resourceService;
    private CredentialInternalService credentialService;

    @Autowired
    public void setAttributeEngine(AttributeEngine attributeEngine) {
        this.attributeEngine = attributeEngine;
    }

    @Autowired
    public void setResourceService(ResourceInternalService resourceService) {
        this.resourceService = resourceService;
    }

    @Autowired
    public void setCredentialService(CredentialInternalService credentialService) {
        this.credentialService = credentialService;
    }


    public List<RequestAttribute> prepareRequestAttributesForConnectorRequest(UUID connectorUuid, List<BaseAttribute> attributeDefinitions, List<RequestAttribute> requestAttributes) throws AttributeException, NotFoundException, ConnectorException {
        attributeEngine.validateUpdateDataAttributes(connectorUuid, null, attributeDefinitions, requestAttributes);
        return resolveContent(connectorUuid, requestAttributes);
    }

    /**
     * Dereferences CREDENTIAL + RESOURCE (incl. SECRET) references in attributes that were already stored and
     * validated, so a stateless connector receives inline content on the operation path. Unlike
     * {@link #prepareRequestAttributesForConnectorRequest}, this does not re-validate — the attributes were validated
     * when persisted and no attribute definitions are supplied. Callers resolving an authority's own infrastructure
     * references go through {@code OperationAttributeResolver}, which elevates to the platform's attribute-resolver
     * system identity for the duration of this call (authorized at the operation level, not per acting caller).
     * <p>
     * Unlike the callback reference expander, this does not arm outbound-secret value-echo containment: an operation
     * response maps to certificate data, not reflected back to an untrusted caller surface.
     */
    public List<RequestAttribute> dereferenceForConnectorRequest(UUID connectorUuid, List<RequestAttribute> requestAttributes) throws AttributeException, NotFoundException, ConnectorException {
        return resolveContent(connectorUuid, requestAttributes);
    }

    /** Shared skeleton: resolve request-attribute content against the connector's definitions, dereferencing
     * CREDENTIAL + RESOURCE (incl. SECRET) references in place, then map back to client attributes. */
    private List<RequestAttribute> resolveContent(UUID connectorUuid, List<RequestAttribute> requestAttributes) throws AttributeException, NotFoundException, ConnectorException {
        List<DataAttribute> dataAttributes = attributeEngine.getDataAttributesByContent(connectorUuid, requestAttributes);
        credentialService.loadFullCredentialData(dataAttributes);
        resourceService.loadResourceObjectContentData(dataAttributes);
        return AttributeDefinitionUtils.getClientAttributes(dataAttributes);
    }
}
