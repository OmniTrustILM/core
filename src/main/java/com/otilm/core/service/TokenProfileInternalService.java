package com.otilm.core.service;

import com.otilm.api.exception.NotFoundException;
import com.otilm.core.dao.entity.TokenProfile;
import com.otilm.core.security.authz.SecuredUUID;

public interface TokenProfileInternalService extends ResourceExtensionService {
    /**
     * Get the details of a token profile which has Token Instance association. Internal Method only without authorization
     *
     * @param uuid              - UUID of the Token Profile
     * @return Details of the token Profile {@Link TokenProfileDetailDto}
     * @throws NotFoundException When the token instance or token profile is not found
     */
    TokenProfile getTokenProfileEntity(SecuredUUID uuid) throws NotFoundException;
}
