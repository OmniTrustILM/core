package com.otilm.core.service;

import com.otilm.api.exception.AlreadyExistException;
import com.otilm.api.exception.AttributeException;
import com.otilm.api.exception.ConnectorException;
import com.otilm.api.exception.NotFoundException;
import com.otilm.api.model.client.certificate.SearchRequestDto;
import com.otilm.api.model.common.PaginationResponseDto;
import com.otilm.api.model.common.attribute.common.BaseAttribute;
import com.otilm.api.model.connector.secrets.SecretType;
import com.otilm.api.model.core.search.SearchFieldDataByGroupDto;
import com.otilm.api.model.core.vaultprofile.*;
import com.otilm.core.dao.entity.VaultProfile;
import com.otilm.core.security.authz.SecuredParentUUID;
import com.otilm.core.security.authz.SecuredUUID;
import com.otilm.core.security.authz.SecurityFilter;

import java.util.List;

public interface VaultProfileService extends ResourceExtensionService {

    PaginationResponseDto<VaultProfileDto> listVaultProfiles(SearchRequestDto searchRequest, SecurityFilter securityFilter);

    VaultProfileDetailDto getVaultProfileDetails(SecuredParentUUID vaultUuid, SecuredUUID vaultProfileUuid) throws NotFoundException;

    /**
     * Internal, unauthorized accessor for the {@link VaultProfile} entity by UUID. Unlike
     * {@link #getVaultProfileDetails}, this performs no {@code @ExternalAuthorization} check and is not
     * parent-scoped on the vault-instance UUID, so callers that already authorize the operation through
     * their own resource can resolve a vault profile without imposing VAULT/VAULT_PROFILE permissions.
     */
    VaultProfile getVaultProfileEntity(SecuredUUID vaultProfileUuid) throws NotFoundException;

    VaultProfileDetailDto updateVaultProfile(SecuredParentUUID securedParentUUID, SecuredUUID securedUUID, VaultProfileUpdateRequestDto vaultProfileDetail) throws NotFoundException, AttributeException;

    void deleteVaultProfile(SecuredParentUUID securedParentUUID, SecuredUUID securedUUID) throws NotFoundException;

    VaultProfileDetailDto createVaultProfile(SecuredParentUUID securedParentUUID, VaultProfileRequestDto vaultProfileDetail) throws NotFoundException, AttributeException, AlreadyExistException;

    void enableVaultProfile(SecuredParentUUID securedParentUUID, SecuredUUID securedUUID) throws NotFoundException;

    void disableVaultProfile(SecuredParentUUID securedParentUUID, SecuredUUID securedUUID) throws NotFoundException;

    List<BaseAttribute> listSecretAttributes(SecuredParentUUID vaultUUID, SecuredUUID vaultProfileUUID, SecretType secretType) throws NotFoundException, ConnectorException, AttributeException;

    List<SearchFieldDataByGroupDto> getSearchableFieldInformation();

    Long statisticsVaultProfileCount(SecurityFilter filter);
}
