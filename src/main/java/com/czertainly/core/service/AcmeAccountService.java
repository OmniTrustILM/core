package com.czertainly.core.service;

import com.otilm.api.exception.NotFoundException;
import com.otilm.api.model.client.acme.AcmeAccountListResponseDto;
import com.otilm.api.model.client.acme.AcmeAccountResponseDto;
import com.czertainly.core.security.authz.SecuredParentUUID;
import com.czertainly.core.security.authz.SecuredUUID;
import com.czertainly.core.security.authz.SecurityFilter;

import java.util.List;

public interface AcmeAccountService extends ResourceExtensionService {

    void revokeAccount(SecuredParentUUID acmeProfileUuid, SecuredUUID uuid) throws NotFoundException;

    void enableAccount(SecuredParentUUID acmeProfileUuid, SecuredUUID uuid) throws NotFoundException;

    void disableAccount(SecuredParentUUID acmeProfileUuid, SecuredUUID uuid) throws NotFoundException;

    void bulkEnableAccount(List<SecuredUUID> uuids);

    void bulkDisableAccount(List<SecuredUUID> uuids);

    void bulkRevokeAccount(List<SecuredUUID> uuids);

    List<AcmeAccountListResponseDto> listAcmeAccounts(SecurityFilter filter);

    AcmeAccountResponseDto getAcmeAccount(SecuredParentUUID acmeProfileUuid, SecuredUUID uuid) throws NotFoundException;

}
