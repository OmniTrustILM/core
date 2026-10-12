package com.otilm.core.service;

import com.otilm.api.exception.AlreadyExistException;
import com.otilm.api.exception.AttributeException;
import com.otilm.api.exception.ConnectorException;
import com.otilm.api.exception.NotFoundException;
import com.otilm.api.model.client.attribute.RequestAttribute;
import com.otilm.api.model.client.certificate.SearchRequestDto;
import com.otilm.api.model.common.PaginationResponseDto;
import com.otilm.api.model.connector.secrets.content.SecretContent;
import com.otilm.api.model.core.search.SearchFieldDataByGroupDto;
import com.otilm.api.model.core.secret.SecretDetailDto;
import com.otilm.api.model.core.secret.SecretDto;
import com.otilm.api.model.core.secret.SecretRequestDto;
import com.otilm.api.model.core.secret.SecretUpdateObjectsDto;
import com.otilm.api.model.core.secret.SecretUpdateRequestDto;
import com.otilm.api.model.core.secret.SecretVersionDto;
import com.otilm.core.reference.ObjectRef;
import com.otilm.core.security.authz.SecuredParentUUID;
import com.otilm.core.security.authz.SecuredUUID;
import com.otilm.core.security.authz.SecurityFilter;
import java.util.List;
import java.util.UUID;

public interface SecretExternalService {

    List<SearchFieldDataByGroupDto> getSearchableFieldInformation();

    PaginationResponseDto<SecretDto> listSecrets(SearchRequestDto searchRequest, SecurityFilter securityFilter);

    SecretDetailDto createSecret(SecretRequestDto secretRequest, SecuredParentUUID securedParentUUID,
            SecuredUUID securedUUID)
            throws NotFoundException, AttributeException, AlreadyExistException, ConnectorException;

    SecretDetailDto updateSecret(UUID uuid, SecretUpdateRequestDto secretRequest)
            throws NotFoundException, AttributeException, ConnectorException;

    void deleteSecret(UUID uuid, boolean deleteInVaults)
            throws NotFoundException, ConnectorException, AttributeException;

    /**
     * Queues the deletion of a secret, in every vault, for the owner deleted together with it. Only references held by
     * others refuse it.
     */
    void deleteOwnedSecret(UUID uuid, ObjectRef owner) throws NotFoundException, ConnectorException, AttributeException;

    /**
     * Refuses wherever {@link #deleteOwnedSecret} would, deleting nothing, so an owner of several secrets learns of a
     * refusal before it deletes any of them.
     */
    void checkOwnedSecretDeletion(UUID uuid, ObjectRef owner) throws NotFoundException;

    void enableSecret(UUID uuid) throws NotFoundException;

    void disableSecret(UUID uuid) throws NotFoundException;

    void addVaultProfileToSecret(UUID uuid, UUID vaultProfileUuid, List<RequestAttribute> createSecretAttributes)
            throws NotFoundException, ConnectorException, AttributeException;

    void removeVaultProfileFromSecret(UUID uuid, UUID vaultProfileUuid, boolean deleteInVault)
            throws NotFoundException, ConnectorException, AttributeException;

    SecretDetailDto getSecretDetails(UUID uuid) throws NotFoundException;

    List<SecretVersionDto> getSecretVersions(UUID uuid) throws NotFoundException;

    SecretContent getSecretContent(UUID uuid) throws NotFoundException, ConnectorException, AttributeException;

    void updateSecretObjects(UUID uuid, SecretUpdateObjectsDto request)
            throws NotFoundException, ConnectorException, AttributeException;
}
