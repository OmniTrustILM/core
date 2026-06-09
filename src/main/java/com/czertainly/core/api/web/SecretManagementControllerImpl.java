package com.czertainly.core.api.web;

import com.otilm.api.exception.AlreadyExistException;
import com.otilm.api.exception.AttributeException;
import com.otilm.api.exception.ConnectorException;
import com.otilm.api.exception.NotFoundException;
import com.otilm.api.interfaces.core.web.SecretManagementController;
import com.otilm.api.model.client.attribute.RequestAttribute;
import com.otilm.api.model.client.certificate.SearchRequestDto;
import com.otilm.api.model.common.PaginationResponseDto;
import com.otilm.api.model.connector.secrets.content.SecretContent;
import com.otilm.api.model.core.auth.Resource;
import com.otilm.api.model.core.logging.enums.Module;
import com.otilm.api.model.core.logging.enums.Operation;
import com.otilm.api.model.core.search.SearchFieldDataByGroupDto;
import com.otilm.api.model.core.secret.*;
import com.czertainly.core.aop.AuditLogged;
import com.czertainly.core.logging.LogResource;
import com.czertainly.core.security.authz.SecuredParentUUID;
import com.czertainly.core.security.authz.SecuredUUID;
import com.czertainly.core.security.authz.SecurityFilter;
import com.czertainly.core.service.SecretService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;
import java.util.UUID;


@RestController
public class SecretManagementControllerImpl implements SecretManagementController {

    private SecretService secretService;

    @Autowired
    public void setSecretService(SecretService secretService) {
        this.secretService = secretService;
    }

    @Override
    @AuditLogged(module = Module.SECRETS, resource = Resource.SEARCH_FILTER, operation = Operation.LIST, affiliatedResource = Resource.SECRET)
    public List<SearchFieldDataByGroupDto> getSearchableFieldInformation() {
        return secretService.getSearchableFieldInformation();
    }

    @Override
    @AuditLogged(module = Module.SECRETS, resource = Resource.SECRET, operation = Operation.LIST)
    public PaginationResponseDto<SecretDto> listSecrets(SearchRequestDto searchRequest) {
        return secretService.listSecrets(searchRequest, SecurityFilter.create());
    }

    @Override
    @AuditLogged(module = Module.SECRETS, resource = Resource.SECRET, operation = Operation.DETAIL)
    public SecretDetailDto getSecretDetails(@LogResource(uuid = true) UUID uuid) throws NotFoundException {
        return secretService.getSecretDetails(uuid);
    }

    @Override
    @AuditLogged(module = Module.SECRETS, resource = Resource.SECRET, operation = Operation.LIST_VERSIONS)
    public List<SecretVersionDto> getSecretVersions(@LogResource(uuid = true) UUID uuid) throws NotFoundException {
        return secretService.getSecretVersions(uuid);
    }

    @Override
    @AuditLogged(module = Module.SECRETS, resource = Resource.SECRET, operation = Operation.GET_CONTENT)
    public SecretContent getSecretContent(@LogResource(uuid = true) UUID uuid) throws NotFoundException, ConnectorException, AttributeException {
        return secretService.getSecretContent(uuid);
    }

    @Override
    @AuditLogged(module = Module.SECRETS, resource = Resource.SECRET, operation = Operation.CREATE, affiliatedResource = Resource.VAULT)
    public SecretDetailDto createSecret(SecretRequestDto secretRequest, @LogResource(uuid = true, affiliated = true) UUID vaultProfileUuid, UUID vaultUuid) throws NotFoundException, AttributeException, AlreadyExistException, ConnectorException {
        return secretService.createSecret(secretRequest, SecuredParentUUID.fromUUID(vaultProfileUuid), SecuredUUID.fromUUID(vaultUuid));
    }

    @Override
    @AuditLogged(module = Module.SECRETS, resource = Resource.SECRET, operation = Operation.UPDATE)
    public SecretDetailDto updateSecret(@LogResource(uuid = true) UUID uuid, SecretUpdateRequestDto secretRequest) throws NotFoundException, AttributeException, ConnectorException {
        return secretService.updateSecret(uuid, secretRequest);
    }

    @Override
    @AuditLogged(module = Module.SECRETS, resource = Resource.SECRET, operation = Operation.DELETE)
    public void deleteSecret(@LogResource(uuid = true) UUID uuid, boolean deleteInVaults) throws NotFoundException, ConnectorException, AttributeException {
        secretService.deleteSecret(uuid, deleteInVaults);
    }

    @Override
    @AuditLogged(module = Module.SECRETS, resource = Resource.SECRET, operation = Operation.ENABLE)
    public void enableSecret(@LogResource(uuid = true) UUID uuid) throws NotFoundException {
        secretService.enableSecret(uuid);
    }

    @Override
    @AuditLogged(module = Module.SECRETS, resource = Resource.SECRET, operation = Operation.DISABLE)
    public void disableSecret(@LogResource(uuid = true) UUID uuid) throws NotFoundException {
        secretService.disableSecret(uuid);
    }

    @Override
    @AuditLogged(module = Module.SECRETS, resource = Resource.SECRET, affiliatedResource = Resource.VAULT_PROFILE, operation = Operation.ASSOCIATE)
    public void addVaultProfileToSecret(@LogResource(uuid = true) UUID uuid, @LogResource(uuid = true, affiliated = true) UUID vaultProfileUuid, List<RequestAttribute> createSecretAttributes) throws NotFoundException, ConnectorException, AttributeException {
        secretService.addVaultProfileToSecret(uuid, vaultProfileUuid, createSecretAttributes);
    }

    @Override
    @AuditLogged(module = Module.SECRETS, resource = Resource.SECRET, affiliatedResource = Resource.VAULT_PROFILE, operation = Operation.DISASSOCIATE)
    public void removeVaultProfileFromSecret(@LogResource(uuid = true) UUID uuid, @LogResource(uuid = true, affiliated = true) UUID vaultProfileUuid, boolean deleteInVault) throws NotFoundException, ConnectorException, AttributeException {
        secretService.removeVaultProfileFromSecret(uuid, vaultProfileUuid, deleteInVault);
    }

    @Override
    @AuditLogged(module = Module.SECRETS, resource = Resource.SECRET, operation = Operation.UPDATE)
    public void updateSecretObjects(@LogResource(uuid = true) UUID uuid, SecretUpdateObjectsDto request) throws NotFoundException, ConnectorException, AttributeException {
        secretService.updateSecretObjects(uuid, request);
    }
}
