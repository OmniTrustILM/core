package com.czertainly.core.service;

import com.czertainly.api.exception.AlreadyExistException;
import com.czertainly.api.exception.AttributeException;
import com.czertainly.api.exception.ConnectorException;
import com.czertainly.api.exception.NotFoundException;
import com.czertainly.api.model.common.UuidDto;
import com.czertainly.api.model.core.connector.v2.ConnectorDetailDto;
import com.czertainly.api.model.core.connector.v2.ConnectorRequestDto;

public interface ConnectorRegistrationExternalService {

    UuidDto registerConnector(com.czertainly.api.model.client.connector.ConnectorRequestDto request) throws AlreadyExistException, ConnectorException, AttributeException, NotFoundException;

    ConnectorDetailDto registerConnectorV2(ConnectorRequestDto request) throws AlreadyExistException, ConnectorException, AttributeException, NotFoundException;
}
