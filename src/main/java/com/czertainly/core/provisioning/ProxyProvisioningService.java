package com.czertainly.core.provisioning;

/**
 * Service for managing proxy lifecycle through the external provisioning API.
 */
public interface ProxyProvisioningService {

    /**
     * Provisions a new proxy and returns installation instructions.
     *
     * @param proxyCode unique identifier for the proxy
     * @throws ProvisioningException if provisioning fails
     */
    void provisionProxy(String proxyCode) throws ProvisioningException;

    /**
     * Retrieves installation instructions for an existing proxy.
     *
     * @param proxyCode unique identifier for the proxy
     * @return installation instructions as a shell command
     * @throws ProvisioningException if retrieval fails
     */
    String getProxyInstallationInstructions(String proxyCode) throws ProvisioningException;

    /**
     * Decommissions an existing proxy.
     *
     * @param proxyCode unique identifier for the proxy
     * @throws ProvisioningException if decommissioning fails
     */
    void decommissionProxy(String proxyCode) throws ProvisioningException;
}
