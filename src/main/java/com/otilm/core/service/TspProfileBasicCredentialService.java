package com.otilm.core.service;

import com.otilm.api.exception.AlreadyExistException;
import com.otilm.api.exception.AttributeException;
import com.otilm.api.exception.ConnectorCommunicationException;
import com.otilm.api.exception.NotFoundException;
import com.otilm.api.model.client.signing.protocols.tsp.TspBasicCredentialDto;
import com.otilm.api.model.client.signing.protocols.tsp.TspBasicCredentialRequestDto;
import com.otilm.core.security.authz.SecuredParentUUID;
import com.otilm.core.security.authz.SecuredUUID;

import java.util.List;
import java.util.UUID;

public interface TspProfileBasicCredentialService {

    List<TspBasicCredentialDto> list(SecuredParentUUID tspProfileUuid) throws NotFoundException;

    TspBasicCredentialDto get(SecuredParentUUID tspProfileUuid, SecuredUUID uuid) throws NotFoundException;

    TspBasicCredentialDto create(SecuredParentUUID tspProfileUuid, TspBasicCredentialRequestDto request) throws AlreadyExistException, AttributeException, ConnectorCommunicationException, NotFoundException;

    TspBasicCredentialDto update(SecuredParentUUID tspProfileUuid, SecuredUUID uuid, TspBasicCredentialRequestDto request) throws AlreadyExistException, AttributeException, ConnectorCommunicationException, NotFoundException;

    void delete(SecuredParentUUID tspProfileUuid, SecuredUUID uuid) throws AttributeException, ConnectorCommunicationException, NotFoundException;

    /**
     * Deletes the vault secret backing every Basic credential of the given TSP profile.
     * Runs without an ambient transaction so the vault HTTP calls never hold a database transaction open.
     */
    void deleteSecretsForProfile(UUID tspProfileUuid);
}
