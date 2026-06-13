package com.otilm.core.service;

import com.otilm.api.exception.NotFoundException;
import com.otilm.core.dao.entity.VaultProfile;
import com.otilm.core.security.authz.SecuredUUID;
import com.otilm.core.security.authz.SecurityFilter;

public interface VaultProfileInternalService extends ResourceExtensionService {

    /**
     * Internal, unauthorized accessor for the {@link VaultProfile} entity by UUID. Unlike
     * {@link #getVaultProfileDetails}, this performs no {@code @ExternalAuthorization} check and is not
     * parent-scoped on the vault-instance UUID, so callers that already authorize the operation through
     * their own resource can resolve a vault profile without imposing VAULT/VAULT_PROFILE permissions.
     */
    VaultProfile getVaultProfileEntity(SecuredUUID vaultProfileUuid) throws NotFoundException;

    Long statisticsVaultProfileCount(SecurityFilter filter);
}
