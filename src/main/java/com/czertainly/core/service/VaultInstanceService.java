package com.czertainly.core.service;


import com.otilm.api.clients.ApiClientConnectorInfo;
import com.otilm.api.exception.AlreadyExistException;
import com.otilm.api.exception.AttributeException;
import com.otilm.api.exception.ConnectorException;
import com.otilm.api.exception.NotFoundException;
import com.otilm.api.model.client.certificate.SearchRequestDto;
import com.otilm.api.model.common.PaginationResponseDto;
import com.otilm.api.model.common.attribute.common.BaseAttribute;
import com.otilm.api.model.connector.secrets.SecretOperationRequest;
import com.otilm.api.model.core.search.SearchFieldDataByGroupDto;
import com.otilm.api.model.core.vault.*;
import com.czertainly.core.security.authz.SecuredUUID;
import com.czertainly.core.security.authz.SecurityFilter;

import java.util.List;
import java.util.UUID;

public interface VaultInstanceService {


    VaultInstanceDetailDto createVaultInstance(VaultInstanceRequestDto vaultInstanceRequest) throws ConnectorException, NotFoundException, AttributeException, AlreadyExistException;

    VaultInstanceDetailDto getVaultInstance(UUID uuid) throws ConnectorException, NotFoundException, AttributeException;

    PaginationResponseDto<VaultInstanceDto> listVaultInstances(SearchRequestDto searchRequest, SecurityFilter securityFilter);

    void deleteVaultInstance(UUID uuid) throws NotFoundException;

    VaultInstanceDetailDto updateVaultInstance(UUID uuid, VaultInstanceUpdateRequestDto vaultInstanceRequest) throws NotFoundException, AttributeException, ConnectorException;

    List<SearchFieldDataByGroupDto> getSearchableFieldInformation();

    List<BaseAttribute> listVaultInstanceAttributes(UUID connectorUuid) throws ConnectorException, NotFoundException, AttributeException;

    List<BaseAttribute> listVaultProfileAttributes(SecuredUUID vaultInstanceUuid) throws ConnectorException, NotFoundException, AttributeException;

    void loadAttributesForSecretOperation(ApiClientConnectorInfo connector, UUID vaultInstanceUuid, UUID vaultProfileUuid, SecretOperationRequest secretOperationRequest) throws NotFoundException, ConnectorException, AttributeException;

    Long statisticsVaultInstanceCount(SecurityFilter filter);
}
