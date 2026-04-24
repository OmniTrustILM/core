package com.czertainly.core.service;

import com.czertainly.api.exception.AlreadyExistException;
import com.czertainly.api.exception.NotFoundException;
import com.czertainly.api.model.client.proxy.ProxyRequestDto;
import com.czertainly.api.model.client.proxy.ProxyUpdateRequestDto;
import com.czertainly.api.model.core.proxy.ProxyDto;
import com.czertainly.api.model.core.proxy.ProxyInstallInstructionsDto;
import com.czertainly.api.model.core.proxy.ProxyListDto;
import com.czertainly.api.model.core.proxy.ProxyStatus;
import com.czertainly.core.dao.entity.Proxy;
import com.czertainly.core.security.authz.SecuredUUID;
import com.czertainly.core.security.authz.SecurityFilter;

import java.util.List;
import java.util.Optional;

/**
 * Service for managing proxy entities.
 */
public interface ProxyService extends ResourceExtensionService {

    /**
     * Lists all proxies accessible by the current user, optionally filtered by status.
     *
     * @param filter security filter for access control
     * @param status optional status to filter proxies
     * @return list of proxy listing DTOs ({@link ProxyListDto})
     */
    List<ProxyListDto> listProxies(SecurityFilter filter, Optional<ProxyStatus> status);

    /**
     * Retrieves a proxy by its UUID.
     *
     * @param uuid the proxy UUID
     * @return proxy DTO with details
     * @throws NotFoundException if proxy not found
     */
    ProxyDto getProxy(SecuredUUID uuid) throws NotFoundException;

    /**
     * Retrieves a proxy entity by its UUID.
     *
     * @param uuid the proxy UUID
     * @return proxy entity
     * @throws NotFoundException if proxy not found
     */
    Proxy getProxyEntity(SecuredUUID uuid) throws NotFoundException;

    /**
     * Creates a new proxy and provisions it via the external provisioning API.
     *
     * @param request proxy creation request
     * @return created proxy DTO
     * @throws AlreadyExistException if proxy with the same name already exists
     */
    ProxyDto createProxy(ProxyRequestDto request) throws AlreadyExistException;

    /**
     * Updates an existing proxy.
     *
     * @param uuid    the proxy UUID
     * @param request proxy update request
     * @return updated proxy DTO
     * @throws NotFoundException if proxy not found
     */
    ProxyDto editProxy(SecuredUUID uuid, ProxyUpdateRequestDto request) throws NotFoundException;

    /**
     * Deletes a proxy and decommissions it via the external provisioning API.
     *
     * @param uuid the proxy UUID
     * @throws NotFoundException if proxy not found
     */
    void deleteProxy(SecuredUUID uuid) throws NotFoundException;

    /**
     * Retrieves installation instructions for a proxy.
     *
     * @param uuid the proxy UUID
     * @return DTO with installation instructions
     * @throws NotFoundException if proxy not found
     */
    ProxyInstallInstructionsDto getInstallationInstructions(SecuredUUID uuid) throws NotFoundException;
}
