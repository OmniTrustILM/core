package com.czertainly.core.attribute.engine;

import com.otilm.api.exception.AttributeException;
import com.otilm.api.exception.ConnectorException;
import com.otilm.api.exception.NotFoundException;
import com.otilm.api.model.client.attribute.RequestAttribute;
import com.otilm.api.model.common.attribute.common.BaseAttribute;
import com.otilm.api.model.common.attribute.common.DataAttribute;
import com.czertainly.core.service.CredentialService;
import com.czertainly.core.service.ResourceInternalService;
import com.otilm.core.util.AttributeDefinitionUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import java.util.List;
import java.util.UUID;

@Component
public class ConnectorRequestAttributesBuilder {

    private AttributeEngine attributeEngine;
    private ResourceInternalService resourceService;
    private CredentialService credentialService;

    @Autowired
    public void setAttributeEngine(AttributeEngine attributeEngine) {
        this.attributeEngine = attributeEngine;
    }

    @Autowired
    public void setResourceService(ResourceInternalService resourceService) {
        this.resourceService = resourceService;
    }

    @Autowired
    public void setCredentialService(CredentialService credentialService) {
        this.credentialService = credentialService;
    }


    public List<RequestAttribute> prepareRequestAttributesForConnectorRequest(UUID connectorUuid, List<BaseAttribute> attributeDefinitions, List<RequestAttribute> requestAttributes) throws AttributeException, NotFoundException, ConnectorException {
        attributeEngine.validateUpdateDataAttributes(connectorUuid, null, attributeDefinitions, requestAttributes);
        List<DataAttribute> dataAttributes = attributeEngine.getDataAttributesByContent(connectorUuid, requestAttributes);
        credentialService.loadFullCredentialData(dataAttributes);
        resourceService.loadResourceObjectContentData(dataAttributes);
        return AttributeDefinitionUtils.getClientAttributes(dataAttributes);
    }
}
