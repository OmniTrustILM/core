package com.otilm.core.service;

import com.otilm.api.exception.AlreadyExistException;
import com.otilm.api.exception.AttributeException;
import com.otilm.api.exception.ConnectorException;
import com.otilm.api.exception.NotFoundException;
import com.otilm.api.model.common.UuidDto;
import com.otilm.api.model.core.connector.v2.ConnectorDetailDto;
import com.otilm.api.model.core.connector.v2.ConnectorRequestDto;

public interface ConnectorRegistrationExternalService {

    UuidDto registerConnector(com.otilm.api.model.client.connector.ConnectorRequestDto request) throws AlreadyExistException, ConnectorException, AttributeException, NotFoundException;

    ConnectorDetailDto registerConnectorV2(ConnectorRequestDto request) throws AlreadyExistException, ConnectorException, AttributeException, NotFoundException;
}
