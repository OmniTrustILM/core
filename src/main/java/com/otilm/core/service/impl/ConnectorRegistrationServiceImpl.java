package com.otilm.core.service.impl;

import com.otilm.api.exception.AlreadyExistException;
import com.otilm.api.exception.AttributeException;
import com.otilm.api.exception.ConnectorException;
import com.otilm.api.exception.NotFoundException;
import com.otilm.api.model.client.connector.v2.ConnectorVersion;
import com.otilm.api.model.common.UuidDto;
import com.otilm.api.model.core.connector.v2.ConnectorDetailDto;
import com.otilm.api.model.core.connector.v2.ConnectorRequestDto;
import com.otilm.core.security.authz.UnauthenticatedEndpoint;
import com.otilm.core.service.ConnectorRegistrationExternalService;
import com.otilm.core.service.v2.ConnectorInternalService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import jakarta.transaction.Transactional;

@Service
@Transactional
public class ConnectorRegistrationServiceImpl implements ConnectorRegistrationExternalService {
    private static final Logger logger = LoggerFactory.getLogger(ConnectorRegistrationServiceImpl.class);

    private ConnectorInternalService connectorService;

    @Autowired
    public void setConnectorService(ConnectorInternalService connectorService) {
        this.connectorService = connectorService;
    }

    @Override
    @UnauthenticatedEndpoint
    public UuidDto registerConnector(com.otilm.api.model.client.connector.ConnectorRequestDto request) throws AlreadyExistException, ConnectorException, AttributeException, NotFoundException {
        ConnectorRequestDto requestV2 = new ConnectorRequestDto();
        requestV2.setName(request.getName());
        requestV2.setUrl(request.getUrl());
        requestV2.setVersion(ConnectorVersion.V1);
        requestV2.setAuthType(request.getAuthType());
        requestV2.setAuthAttributes(request.getAuthAttributes());
        requestV2.setCustomAttributes(request.getCustomAttributes());
        requestV2.setProxyCode(request.getProxyCode());
        requestV2.setProxyUuid(request.getProxyUuid());

        ConnectorDetailDto connectorDto = connectorService.createNewWaitingConnector(requestV2);
        logger.info("Connector {} registered and is waiting for approval.", request.getName());

        UuidDto dto = new UuidDto();
        dto.setUuid(connectorDto.getUuid());
        return dto;
    }

    @Override
    @UnauthenticatedEndpoint
    public ConnectorDetailDto registerConnectorV2(ConnectorRequestDto request) throws AlreadyExistException, ConnectorException, AttributeException, NotFoundException {
        return connectorService.createNewWaitingConnector(request);
    }
}
