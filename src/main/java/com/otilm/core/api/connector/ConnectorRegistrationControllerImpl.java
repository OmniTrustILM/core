package com.otilm.core.api.connector;

import com.otilm.api.exception.AlreadyExistException;
import com.otilm.api.exception.AttributeException;
import com.otilm.api.exception.ConnectorException;
import com.otilm.api.exception.NotFoundException;
import com.otilm.api.interfaces.core.connector.ConnectorRegistrationController;
import com.otilm.api.model.client.connector.ConnectorRequestDto;
import com.otilm.api.model.common.UuidDto;
import com.otilm.api.model.core.auth.Resource;
import com.otilm.api.model.core.connector.v2.ConnectorDetailDto;
import com.otilm.api.model.core.logging.enums.Module;
import com.otilm.api.model.core.logging.enums.Operation;
import com.otilm.core.aop.AuditLogged;
import com.otilm.core.service.ConnectorRegistrationExternalService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class ConnectorRegistrationControllerImpl implements ConnectorRegistrationController {

    private ConnectorRegistrationExternalService connectorRegistrationService;

    @Autowired
    public void setConnectorRegistrationService(ConnectorRegistrationExternalService connectorRegistrationService) {
        this.connectorRegistrationService = connectorRegistrationService;
    }

    @Override
    @AuditLogged(module = Module.CORE, resource = Resource.CONNECTOR, operation = Operation.REGISTER)
    public UuidDto register(@RequestBody ConnectorRequestDto request) throws ConnectorException, AlreadyExistException, AttributeException, NotFoundException {
        return connectorRegistrationService.registerConnector(request);
    }

    @Override
    public ConnectorDetailDto register(com.otilm.api.model.core.connector.v2.ConnectorRequestDto request) throws ConnectorException, AlreadyExistException, AttributeException, NotFoundException {
        return connectorRegistrationService.registerConnectorV2(request);
    }
}
