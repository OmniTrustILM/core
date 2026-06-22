package com.otilm.core.service;

import com.otilm.api.exception.NotFoundException;
import com.otilm.core.dao.entity.Proxy;
import com.otilm.core.security.authz.SecuredUUID;

/**
 * Internal service for managing proxy entities. Methods are intended for internal use only,
 * without authorization checks performed at this layer.
 */
public interface ProxyInternalService extends ResourceExtensionService {

    /**
     * Retrieves a proxy entity by its UUID.
     *
     * @param uuid the proxy UUID
     * @return proxy entity
     * @throws NotFoundException if proxy not found
     */
    Proxy getProxyEntity(SecuredUUID uuid) throws NotFoundException;
}
