package com.otilm.core.service;

import com.otilm.api.exception.*;
import com.otilm.api.model.client.credential.CredentialRequestDto;
import com.otilm.api.model.client.credential.CredentialUpdateRequestDto;
import com.otilm.api.model.core.credential.CredentialDto;
import com.otilm.core.security.authz.SecuredUUID;
import com.otilm.core.security.authz.SecurityFilter;

import java.util.List;

public interface CredentialExternalService {
    List<CredentialDto> listCredentials(SecurityFilter filter);

    CredentialDto getCredential(SecuredUUID uuid) throws NotFoundException;

    CredentialDto createCredential(CredentialRequestDto request) throws AlreadyExistException, ConnectorException, AttributeException, NotFoundException;

    CredentialDto editCredential(SecuredUUID uuid, CredentialUpdateRequestDto request) throws ConnectorException, AttributeException, NotFoundException;

    void deleteCredential(SecuredUUID uuid) throws NotFoundException;

    void enableCredential(SecuredUUID uuid) throws NotFoundException;

    void disableCredential(SecuredUUID uuid) throws NotFoundException;

    void bulkDeleteCredential(List<SecuredUUID> uuids) throws ValidationException, NotFoundException;
}
