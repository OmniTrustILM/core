package com.otilm.core.service;

import com.otilm.api.exception.AlreadyExistException;
import com.otilm.api.exception.AttributeException;
import com.otilm.api.exception.ConnectorCommunicationException;
import com.otilm.api.exception.NotFoundException;
import com.otilm.api.model.client.signing.protocols.tsp.TspBasicCredentialCreateRequestDto;
import com.otilm.api.model.client.signing.protocols.tsp.TspBasicCredentialDto;
import com.otilm.api.model.client.signing.protocols.tsp.TspBasicCredentialUpdateRequestDto;
import com.otilm.core.security.authz.SecuredParentUUID;
import com.otilm.core.security.authz.SecuredUUID;

import java.util.List;

public interface TspProfileBasicCredentialExternalService {

    List<TspBasicCredentialDto> list(SecuredParentUUID tspProfileUuid) throws NotFoundException;

    TspBasicCredentialDto get(SecuredParentUUID tspProfileUuid, SecuredUUID uuid) throws NotFoundException;

    TspBasicCredentialDto create(SecuredParentUUID tspProfileUuid, TspBasicCredentialCreateRequestDto request) throws AlreadyExistException, AttributeException, ConnectorCommunicationException, NotFoundException;

    TspBasicCredentialDto update(SecuredParentUUID tspProfileUuid, SecuredUUID uuid, TspBasicCredentialUpdateRequestDto request) throws AlreadyExistException, AttributeException, ConnectorCommunicationException, NotFoundException;

    void delete(SecuredParentUUID tspProfileUuid, SecuredUUID uuid) throws AttributeException, ConnectorCommunicationException, NotFoundException;
}
