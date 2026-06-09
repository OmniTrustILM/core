package com.czertainly.core.api.web;

import com.otilm.api.exception.NotFoundException;
import com.otilm.api.interfaces.core.web.AcmeAccountController;
import com.otilm.api.model.client.acme.AcmeAccountListResponseDto;
import com.otilm.api.model.client.acme.AcmeAccountResponseDto;
import com.otilm.api.model.core.auth.Resource;
import com.otilm.api.model.core.logging.enums.Module;
import com.otilm.api.model.core.logging.enums.Operation;
import com.czertainly.core.aop.AuditLogged;
import com.czertainly.core.logging.LogResource;
import com.czertainly.core.security.authz.SecuredParentUUID;
import com.czertainly.core.security.authz.SecuredUUID;
import com.czertainly.core.security.authz.SecurityFilter;
import com.czertainly.core.service.AcmeAccountExternalService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;

@RestController
public class AcmeAccountControllerImpl implements AcmeAccountController {

    private AcmeAccountExternalService acmeAccountService;

    @Autowired
    public void setAcmeAccountService(AcmeAccountExternalService acmeAccountService) {
        this.acmeAccountService = acmeAccountService;
    }

    @Override
    @AuditLogged(module = Module.PROTOCOLS, resource = Resource.ACME_ACCOUNT, operation = Operation.REVOKE)
    public void revokeAcmeAccount(String acmeProfileUuid, @LogResource(uuid = true) String acmeAccountUuid) throws NotFoundException {
        acmeAccountService.revokeAccount(SecuredParentUUID.fromString(acmeProfileUuid), SecuredUUID.fromString(acmeAccountUuid));
    }

    @Override
    @AuditLogged(module = Module.PROTOCOLS, resource = Resource.ACME_ACCOUNT, operation = Operation.ENABLE)
    public void bulkEnableAcmeAccount(@LogResource(uuid = true) List<String> uuids) throws NotFoundException {
        acmeAccountService.bulkEnableAccount(SecuredUUID
                .fromList(uuids));
    }

    @Override
    @AuditLogged(module = Module.PROTOCOLS, resource = Resource.ACME_ACCOUNT, operation = Operation.DISABLE)
    public void bulkDisableAcmeAccount(@LogResource(uuid = true) List<String> uuids) throws NotFoundException {
        acmeAccountService.bulkDisableAccount(SecuredUUID.fromList(uuids));
    }

    @Override
    @AuditLogged(module = Module.PROTOCOLS, resource = Resource.ACME_ACCOUNT, operation = Operation.REVOKE)
    public void bulkRevokeAcmeAccount(@LogResource(uuid = true) List<String> uuids) throws NotFoundException {
        acmeAccountService.bulkRevokeAccount(SecuredUUID.fromList(uuids));
    }

    @Override
    @AuditLogged(module = Module.PROTOCOLS, resource = Resource.ACME_ACCOUNT, operation = Operation.LIST)
    public List<AcmeAccountListResponseDto> listAcmeAccounts() {
        return acmeAccountService.listAcmeAccounts(SecurityFilter.create());
    }

    @Override
    @AuditLogged(module = Module.PROTOCOLS, resource = Resource.ACME_ACCOUNT, operation = Operation.DETAIL)
    public AcmeAccountResponseDto getAcmeAccount(String acmeProfileUuid, @LogResource(uuid = true) String acmeAccountUuid) throws NotFoundException {
        return acmeAccountService.getAcmeAccount(SecuredParentUUID.fromString(acmeProfileUuid), SecuredUUID.fromString(acmeAccountUuid));
    }

    @Override
    @AuditLogged(module = Module.PROTOCOLS, resource = Resource.ACME_ACCOUNT, operation = Operation.ENABLE)
    public void enableAcmeAccount(String acmeProfileUuid, @LogResource(uuid = true) String acmeAccountUuid) throws NotFoundException {
        acmeAccountService.enableAccount(SecuredParentUUID.fromString(acmeProfileUuid), SecuredUUID.fromString(acmeAccountUuid));
    }

    @Override
    @AuditLogged(module = Module.PROTOCOLS, resource = Resource.ACME_ACCOUNT, operation = Operation.DISABLE)
    public void disableAcmeAccount(String acmeProfileUuid, @LogResource(uuid = true) String acmeAccountUuid) throws NotFoundException {
        acmeAccountService.disableAccount(SecuredParentUUID.fromString(acmeProfileUuid), SecuredUUID.fromString(acmeAccountUuid));
    }
}
