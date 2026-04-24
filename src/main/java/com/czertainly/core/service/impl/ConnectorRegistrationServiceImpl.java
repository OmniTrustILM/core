package com.czertainly.core.service.impl;

import com.czertainly.api.exception.AlreadyExistException;
import com.czertainly.api.exception.AttributeException;
import com.czertainly.api.exception.ConnectorException;
import com.czertainly.api.exception.NotFoundException;
import com.czertainly.api.model.client.connector.v2.ConnectorVersion;
import com.czertainly.api.model.common.UuidDto;
import com.czertainly.api.model.core.connector.v2.ConnectorDetailDto;
import com.czertainly.api.model.core.connector.v2.ConnectorRequestDto;
import com.czertainly.core.service.ConnectorRegistrationService;
import com.czertainly.core.service.v2.ConnectorService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import jakarta.transaction.Transactional;

@Service
@Transactional
public class ConnectorRegistrationServiceImpl implements ConnectorRegistrationService {
    private static final Logger logger = LoggerFactory.getLogger(ConnectorRegistrationServiceImpl.class);

    private ConnectorService connectorService;

    @Autowired
    public void setConnectorService(ConnectorService connectorService) {
        this.connectorService = connectorService;
    }

    @Override
    public UuidDto registerConnector(com.czertainly.api.model.client.connector.ConnectorRequestDto request) throws AlreadyExistException, ConnectorException, AttributeException, NotFoundException {
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
    public ConnectorDetailDto registerConnectorV2(ConnectorRequestDto request) throws AlreadyExistException, ConnectorException, AttributeException, NotFoundException {
        return connectorService.createNewWaitingConnector(request);
    }
}
