package com.otilm.core.service;

import com.otilm.api.exception.*;
import com.otilm.api.model.client.attribute.RequestAttribute;
import com.otilm.api.model.client.certificate.SearchRequestDto;
import com.otilm.api.model.client.dashboard.StatisticsDto;
import com.otilm.api.model.common.PaginationResponseDto;
import com.otilm.api.model.connector.secrets.content.SecretContent;
import com.otilm.api.model.core.search.SearchFieldDataByGroupDto;
import com.otilm.api.model.core.secret.*;
import com.otilm.core.messaging.model.ActionMessage;
import com.otilm.core.security.authz.SecuredParentUUID;
import com.otilm.core.security.authz.SecuredUUID;
import com.otilm.core.security.authz.SecurityFilter;
import com.fasterxml.jackson.core.JsonProcessingException;

import java.util.List;
import java.util.Map;
import java.util.UUID;

public interface SecretService extends ResourceExtensionService {

    List<SearchFieldDataByGroupDto> getSearchableFieldInformation();

    PaginationResponseDto<SecretDto> listSecrets(SearchRequestDto searchRequest, SecurityFilter securityFilter);

    SecretDetailDto createSecret(SecretRequestDto secretRequest, SecuredParentUUID securedParentUUID, SecuredUUID securedUUID) throws NotFoundException, AttributeException, AlreadyExistException, ConnectorException;

    SecretDetailDto updateSecret(UUID uuid, SecretUpdateRequestDto secretRequest) throws NotFoundException, AttributeException, ConnectorException;

    void deleteSecret(UUID uuid, boolean deleteInVaults) throws NotFoundException, ConnectorException, AttributeException;

    void enableSecret(UUID uuid) throws NotFoundException;

    void disableSecret(UUID uuid) throws NotFoundException;

    void addVaultProfileToSecret(UUID uuid, UUID vaultProfileUuid, List<RequestAttribute> createSecretAttributes) throws NotFoundException, ConnectorException, AttributeException;

    void removeVaultProfileFromSecret(UUID uuid, UUID vaultProfileUuid, boolean deleteInVault) throws NotFoundException, ConnectorException, AttributeException;

    SecretDetailDto getSecretDetails(UUID uuid) throws NotFoundException;

    List<SecretVersionDto> getSecretVersions(UUID uuid) throws NotFoundException;

    /**
     * Batch lookup of the latest-version fingerprint for each given secret.
     */
    Map<UUID, String> getLatestFingerprintsByUuid(List<UUID> secretUuids);

    SecretContent getSecretContent(UUID uuid) throws NotFoundException, ConnectorException, AttributeException;

    void updateSecretObjects(UUID uuid, SecretUpdateObjectsDto request) throws NotFoundException, ConnectorException, AttributeException;

    void approvalCreatedAction(UUID resourceUuid) throws NotFoundException;

    void processSecretAction(ActionMessage actionMessage, boolean hasApproval, boolean isApproved) throws ConnectorException, NotFoundException, AttributeException, JsonProcessingException, SecretOperationException;
    Long statisticsSecretCount(SecurityFilter filter);

    StatisticsDto addSecretStatistics(SecurityFilter filter, StatisticsDto dto);
}
