package com.otilm.core.api.web;

import com.otilm.api.exception.AlreadyExistException;
import com.otilm.api.exception.AttributeException;
import com.otilm.api.exception.ConnectorException;
import com.otilm.api.exception.NotFoundException;
import com.otilm.api.interfaces.core.web.VaultInstanceController;
import com.otilm.api.model.client.certificate.SearchRequestDto;
import com.otilm.api.model.common.PaginationResponseDto;
import com.otilm.api.model.common.attribute.common.BaseAttribute;
import com.otilm.api.model.core.auth.Resource;
import com.otilm.api.model.core.logging.enums.Module;
import com.otilm.api.model.core.logging.enums.Operation;
import com.otilm.api.model.core.search.SearchFieldDataByGroupDto;
import com.otilm.api.model.core.vault.*;
import com.otilm.core.aop.AuditLogged;
import com.otilm.core.logging.LogResource;
import com.otilm.core.security.authz.SecuredUUID;
import com.otilm.core.security.authz.SecurityFilter;
import com.otilm.core.service.VaultInstanceService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;
import java.util.UUID;

@RestController
public class VaultInstanceControllerImpl implements VaultInstanceController {

    private final VaultInstanceService vaultInstanceService;

    @Autowired
    public VaultInstanceControllerImpl(VaultInstanceService vaultInstanceService) {
        this.vaultInstanceService = vaultInstanceService;
    }

    @Override
    @AuditLogged(module = Module.SECRETS, resource = Resource.ATTRIBUTE, affiliatedResource = Resource.VAULT, operation = Operation.LIST_ATTRIBUTES)
    public List<BaseAttribute> listVaultInstanceAttributes(UUID connectorUuid) throws ConnectorException, NotFoundException, AttributeException {
        return vaultInstanceService.listVaultInstanceAttributes(connectorUuid);
    }

    @Override
    @AuditLogged(module = Module.SECRETS, resource = Resource.ATTRIBUTE, name = "vaultProfile", affiliatedResource = Resource.VAULT, operation = Operation.LIST_ATTRIBUTES)
    public List<BaseAttribute> listVaultProfileAttributes(@LogResource(uuid = true, affiliated = true) UUID uuid) throws ConnectorException, NotFoundException, AttributeException {
        return vaultInstanceService.listVaultProfileAttributes(SecuredUUID.fromUUID(uuid));
    }

    @Override
    @AuditLogged(module = Module.SECRETS, resource = Resource.VAULT, operation = Operation.DETAIL)
    public VaultInstanceDetailDto getVaultInstanceDetails(@LogResource(uuid = true) UUID uuid) throws ConnectorException, NotFoundException, AttributeException {
        return vaultInstanceService.getVaultInstance(uuid);
    }

    @Override
    @AuditLogged(module = Module.SECRETS, resource = Resource.VAULT, operation = Operation.LIST)
    public PaginationResponseDto<VaultInstanceDto> listVaultInstances(SearchRequestDto searchRequest) {
        return vaultInstanceService.listVaultInstances(searchRequest, SecurityFilter.create());
    }

    @Override
    @AuditLogged(module = Module.SECRETS, resource = Resource.VAULT, operation = Operation.DELETE)
    public void deleteVaultInstance(@LogResource(uuid = true) UUID uuid) throws NotFoundException {
        vaultInstanceService.deleteVaultInstance(uuid);
    }

    @Override
    @AuditLogged(module = Module.SECRETS, resource = Resource.VAULT, operation = Operation.CREATE)
    public VaultInstanceDetailDto createVaultInstance(VaultInstanceRequestDto vaultInstanceRequest) throws ConnectorException, NotFoundException, AttributeException, AlreadyExistException {
        return vaultInstanceService.createVaultInstance(vaultInstanceRequest);
    }

    @Override
    @AuditLogged(module = Module.SECRETS, resource = Resource.VAULT, operation = Operation.UPDATE)
    public VaultInstanceDetailDto updateVaultInstance(@LogResource(uuid = true) UUID uuid, VaultInstanceUpdateRequestDto vaultInstanceRequest) throws NotFoundException, AttributeException, ConnectorException {
        return vaultInstanceService.updateVaultInstance(uuid, vaultInstanceRequest);
    }

    @Override
    @AuditLogged(module = Module.SECRETS, resource = Resource.SEARCH_FILTER, operation = Operation.LIST, affiliatedResource = Resource.VAULT)
    public List<SearchFieldDataByGroupDto> getSearchableFieldInformation() {
        return vaultInstanceService.getSearchableFieldInformation();
    }
}
