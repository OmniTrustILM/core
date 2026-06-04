package com.czertainly.core.messaging.proxy;

import com.czertainly.api.clients.mq.AttributeApiClient;
import com.czertainly.api.clients.mq.AuthorityInstanceApiClient;
import com.czertainly.api.clients.mq.CertificateApiClient;
import com.czertainly.api.clients.mq.ConnectorApiClient;
import com.czertainly.api.clients.mq.CryptographicOperationsApiClient;
import com.czertainly.api.clients.mq.DiscoveryApiClient;
import com.czertainly.api.clients.mq.EndEntityApiClient;
import com.czertainly.api.clients.mq.EndEntityProfileApiClient;
import com.czertainly.api.clients.mq.EntityInstanceApiClient;
import com.czertainly.api.clients.mq.HealthApiClient;
import com.czertainly.api.clients.mq.KeyManagementApiClient;
import com.czertainly.api.clients.mq.LocationApiClient;
import com.czertainly.api.clients.mq.NotificationInstanceApiClient;
import com.czertainly.api.clients.mq.ProxyClient;
import com.czertainly.api.clients.mq.TokenInstanceApiClient;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

/**
 * Configuration class that enables proxy client functionality.
 * Automatically registers ProxyProperties configuration.
 */
@Configuration
@ConditionalOnProperty(name = "proxy.enabled", havingValue = "true")
@EnableConfigurationProperties(ProxyProperties.class)
public class ProxyClientConfig {

    /**
     * Create MQ-based HealthApiClient bean.
     * This bean is used by ConnectorServiceImpl when connector has proxyId set.
     */
    @Bean
    public HealthApiClient mqHealthApiClient(ProxyClient proxyClient) {
        return new HealthApiClient(proxyClient);
    }

    /**
     * Create MQ-based ConnectorApiClient bean.
     * This bean is used when connector has proxyId set to list supported functions.
     */
    @Bean
    public ConnectorApiClient mqConnectorApiClient(ProxyClient proxyClient) {
        return new ConnectorApiClient(proxyClient);
    }

    /**
     * Create MQ-based AttributeApiClient bean.
     * This bean is used when connector has proxyId set to manage attributes.
     */
    @Bean
    public AttributeApiClient mqAttributeApiClient(ProxyClient proxyClient) {
        return new AttributeApiClient(proxyClient);
    }

    /**
     * Create MQ-based DiscoveryApiClient bean.
     * This bean is used when connector has proxyId set to run discoveries.
     */
    @Bean
    public DiscoveryApiClient mqDiscoveryApiClient(ProxyClient proxyClient) {
        return new DiscoveryApiClient(proxyClient);
    }

    /**
     * Create MQ-based EndEntityProfileApiClient bean.
     * This bean is used when connector has proxyId set to manage end entity profiles.
     */
    @Bean
    public EndEntityProfileApiClient mqEndEntityProfileApiClient(ProxyClient proxyClient) {
        return new EndEntityProfileApiClient(proxyClient);
    }

    /**
     * Create MQ-based CertificateApiClient bean.
     * This bean is used when connector has proxyId set for certificate operations.
     */
    @Bean
    public CertificateApiClient mqCertificateApiClient(ProxyClient proxyClient) {
        return new CertificateApiClient(proxyClient);
    }

    /**
     * Create MQ-based AuthorityInstanceApiClient bean.
     * This bean is used when connector has proxyId set for authority instance operations.
     */
    @Bean
    public AuthorityInstanceApiClient mqAuthorityInstanceApiClient(ProxyClient proxyClient) {
        return new AuthorityInstanceApiClient(proxyClient);
    }

    /**
     * Create MQ-based EntityInstanceApiClient bean.
     * This bean is used when connector has proxyId set for entity instance operations.
     */
    @Bean
    public EntityInstanceApiClient mqEntityInstanceApiClient(ProxyClient proxyClient) {
        return new EntityInstanceApiClient(proxyClient);
    }

    /**
     * Create MQ-based LocationApiClient bean.
     * This bean is used when connector has proxyId set for location operations.
     */
    @Bean
    public LocationApiClient mqLocationApiClient(ProxyClient proxyClient) {
        return new LocationApiClient(proxyClient);
    }

    /**
     * Create MQ-based TokenInstanceApiClient bean.
     * This bean is used when connector has proxyId set for token instance operations.
     */
    @Bean
    public TokenInstanceApiClient mqTokenInstanceApiClient(ProxyClient proxyClient) {
        return new TokenInstanceApiClient(proxyClient);
    }

    /**
     * Create MQ-based KeyManagementApiClient bean.
     * This bean is used when connector has proxyId set for key management operations.
     */
    @Bean
    public KeyManagementApiClient mqKeyManagementApiClient(ProxyClient proxyClient) {
        return new KeyManagementApiClient(proxyClient);
    }

    /**
     * Create MQ-based CryptographicOperationsApiClient bean.
     * This bean is used when connector has proxyId set for cryptographic operations.
     */
    @Bean
    public CryptographicOperationsApiClient mqCryptographicOperationsApiClient(ProxyClient proxyClient) {
        return new CryptographicOperationsApiClient(proxyClient);
    }

    /**
     * Create MQ-based v2 CertificateApiClient bean.
     * This bean is used when connector has proxyId set for v2 certificate operations.
     */
    @Bean
    public com.czertainly.api.clients.mq.v2.CertificateApiClient mqCertificateApiClientV2(ProxyClient proxyClient) {
        return new com.czertainly.api.clients.mq.v2.CertificateApiClient(proxyClient);
    }

    /**
     * Create MQ-based ComplianceApiClient bean.
     * This bean is used when connector has proxyId set for compliance operations.
     */
    @Bean
    public com.czertainly.api.clients.mq.ComplianceApiClient mqComplianceApiClient(ProxyClient proxyClient) {
        return new com.czertainly.api.clients.mq.ComplianceApiClient(proxyClient);
    }

    /**
     * Create MQ-based v2 ComplianceApiClient bean.
     * This bean is used when connector has proxyId set for v2 compliance operations.
     */
    @Bean
    public com.czertainly.api.clients.mq.v2.ComplianceApiClient mqComplianceApiClientV2(ProxyClient proxyClient) {
        return new com.czertainly.api.clients.mq.v2.ComplianceApiClient(proxyClient);
    }

    /**
     * Create MQ-based EndEntityApiClient bean.
     * This bean is used when connector has proxyId set for end entity operations.
     */
    @Bean
    public EndEntityApiClient mqEndEntityApiClient(ProxyClient proxyClient) {
        return new EndEntityApiClient(proxyClient);
    }

    /**
     * Create MQ-based NotificationInstanceApiClient bean.
     * This bean is used when connector has proxyId set for notification instance operations.
     */
    @Bean
    public NotificationInstanceApiClient mqNotificationInstanceApiClient(ProxyClient proxyClient) {
        return new NotificationInstanceApiClient(proxyClient);
    }
}
