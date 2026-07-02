package com.otilm.core.service;

import com.otilm.api.clients.ApiClientConnectorInfo;
import com.otilm.api.exception.AttributeException;
import com.otilm.api.exception.ConnectorException;
import com.otilm.api.exception.NotFoundException;
import com.otilm.api.model.client.attribute.RequestAttribute;
import com.otilm.api.model.core.connector.FunctionGroupCode;
import com.otilm.core.dao.entity.Connector;
import com.otilm.core.security.authz.SecuredUUID;

import java.util.List;
import java.util.UUID;

public interface ConnectorInternalService extends ResourceExtensionService {

    Connector getConnectorEntity(SecuredUUID uuid) throws NotFoundException;

    void mergeAndValidateAttributes(SecuredUUID uuid, FunctionGroupCode functionGroup, List<RequestAttribute> attributes, String functionGroupType) throws ConnectorException, AttributeException, NotFoundException;

    ApiClientConnectorInfo getConnectorForApiClient(UUID connectorUuid) throws NotFoundException;
}
