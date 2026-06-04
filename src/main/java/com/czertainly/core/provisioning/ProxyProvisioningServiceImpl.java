package com.czertainly.core.provisioning;

import lombok.RequiredArgsConstructor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

/**
 * Implementation of the proxy provisioning service that communicates with the external provisioning API.
 */
@Service
@RequiredArgsConstructor
public class ProxyProvisioningServiceImpl implements ProxyProvisioningService {

    private static final Logger logger = LoggerFactory.getLogger(ProxyProvisioningServiceImpl.class);

    private final ProxyProvisioningApiClient proxyProvisioningApiClient;
    private final ProvisioningApiProperties properties;

    @Override
    public void provisionProxy(String proxyCode) throws ProvisioningException {
        logger.info("Provisioning proxy: {}", proxyCode);
        try {
            proxyProvisioningApiClient.provisionProxy(new ProxyProvisioningRequestDTO(proxyCode));
        } catch (Exception e) {
            throw new ProvisioningException("Failed to provision proxy " + proxyCode, e);
        }
    }

    @Override
    public String getProxyInstallationInstructions(String proxyCode) throws ProvisioningException {
        logger.info("Fetching installation instructions for proxy: {}", proxyCode);
        try {
            InstallationInstructionsDTO instructions = proxyProvisioningApiClient.getInstallationInstructions(proxyCode, properties.installationFormat());
            return instructions.command().shell();
        } catch (Exception e) {
            throw new ProvisioningException("Failed to get proxy installation instructions " + proxyCode, e);
        }
    }

    @Override
    public void decommissionProxy(String proxyCode) throws ProvisioningException {
        logger.info("Decommissioning proxy: {}", proxyCode);
        try {
            proxyProvisioningApiClient.decommissionProxy(proxyCode);
        } catch (Exception e) {
            throw new ProvisioningException("Failed to decommission proxy " + proxyCode, e);
        }
    }
}
