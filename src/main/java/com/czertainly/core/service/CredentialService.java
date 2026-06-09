package com.czertainly.core.service;

import com.otilm.api.exception.*;
import com.otilm.api.model.client.credential.CredentialRequestDto;
import com.otilm.api.model.client.credential.CredentialUpdateRequestDto;
import com.otilm.api.model.common.NameAndUuidDto;
import com.otilm.api.model.common.attribute.common.DataAttribute;
import com.otilm.api.model.common.attribute.common.callback.AttributeCallback;
import com.otilm.api.model.common.attribute.common.callback.RequestAttributeCallback;
import com.otilm.api.model.core.credential.CredentialDto;
import com.czertainly.core.security.authz.SecuredUUID;
import com.czertainly.core.security.authz.SecurityFilter;

import java.util.List;

public interface CredentialService extends ResourceExtensionService {
    List<CredentialDto> listCredentials(SecurityFilter filter);

    List<NameAndUuidDto> listCredentialsCallback(SecurityFilter filter, String kind);

    CredentialDto getCredential(SecuredUUID uuid) throws NotFoundException;

    CredentialDto createCredential(CredentialRequestDto request) throws AlreadyExistException, ConnectorException, AttributeException, NotFoundException;

    CredentialDto editCredential(SecuredUUID uuid, CredentialUpdateRequestDto request) throws ConnectorException, AttributeException, NotFoundException;

    void deleteCredential(SecuredUUID uuid) throws NotFoundException;

    void enableCredential(SecuredUUID uuid) throws NotFoundException;

    void disableCredential(SecuredUUID uuid) throws NotFoundException;

    void bulkDeleteCredential(List<SecuredUUID> uuids) throws ValidationException, NotFoundException;

    void loadFullCredentialData(List<DataAttribute> attributes) throws NotFoundException;

    void loadFullCredentialData(AttributeCallback callback, RequestAttributeCallback callbackRequest) throws NotFoundException;
}
