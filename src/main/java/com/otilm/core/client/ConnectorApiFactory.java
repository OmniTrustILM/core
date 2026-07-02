package com.otilm.core.client;

import com.otilm.api.clients.ApiClientConnectorInfo;
import com.otilm.api.clients.AttributeApiClient;
import com.otilm.api.clients.AuthorityInstanceApiClient;
import com.otilm.api.clients.CertificateApiClient;
import com.otilm.api.clients.ComplianceApiClient;
import com.otilm.api.clients.ConnectorApiClient;
import com.otilm.api.clients.DiscoveryApiClient;
import com.otilm.api.clients.EndEntityApiClient;
import com.otilm.api.clients.EndEntityProfileApiClient;
import com.otilm.api.clients.EntityInstanceApiClient;
import com.otilm.api.clients.HealthApiClient;
import com.otilm.api.clients.LocationApiClient;
import com.otilm.api.clients.NotificationInstanceApiClient;
import com.otilm.api.clients.cryptography.CryptographicOperationsApiClient;
import com.otilm.api.clients.cryptography.KeyManagementApiClient;
import com.otilm.api.clients.cryptography.TokenInstanceApiClient;
import com.otilm.api.clients.signing.SignatureFormattingApiClient;
import com.otilm.api.interfaces.client.v1.AttributeSyncApiClient;
import com.otilm.api.interfaces.client.v1.signing.SignatureFormattingSyncApiClient;
import com.otilm.api.interfaces.client.v1.AuthorityInstanceSyncApiClient;
import com.otilm.api.interfaces.client.v2.AttributesSyncApiClient;
import com.otilm.api.interfaces.client.v2.CertificateSyncApiClient;
import com.otilm.api.interfaces.client.v2.ComplianceSyncApiClient;
import com.otilm.api.interfaces.client.v2.HealthSyncApiClient;
import com.otilm.api.interfaces.client.v2.InfoSyncApiClient;
import com.otilm.api.interfaces.client.v2.MetricsSyncApiClient;
import com.otilm.api.interfaces.client.v1.ConnectorSyncApiClient;
import com.otilm.api.interfaces.client.v1.CryptographicOperationsSyncApiClient;
import com.otilm.api.interfaces.client.v1.DiscoverySyncApiClient;
import com.otilm.api.interfaces.client.v1.EndEntityProfileSyncApiClient;
import com.otilm.api.interfaces.client.v1.EndEntitySyncApiClient;
import com.otilm.api.interfaces.client.v1.EntityInstanceSyncApiClient;
import com.otilm.api.interfaces.client.v1.KeyManagementSyncApiClient;
import com.otilm.api.interfaces.client.v1.LocationSyncApiClient;
import com.otilm.api.interfaces.client.v1.NotificationInstanceSyncApiClient;
import com.otilm.api.interfaces.client.v1.TokenInstanceSyncApiClient;
import com.otilm.api.interfaces.client.v3.AuthoritySyncApiClient;
import com.otilm.api.exception.NotFoundException;
import com.otilm.api.model.core.proxy.ProxyDto;
import com.otilm.core.service.v2.ConnectorInternalService;
import jakarta.annotation.PostConstruct;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Lazy;
import org.springframework.stereotype.Component;

import java.util.Objects;
import java.util.Optional;
import java.util.UUID;

/**
 * Factory that returns appropriate API client (REST or MQ) based on connector configuration.
 *
 * <p>This factory centralizes the logic for choosing between REST and MQ-based communication
 * with connectors. When a connector has a proxyId set and the corresponding MQ client is
 * available, the MQ client is returned. Otherwise, the REST client is used.</p>
 *
 * <p>Usage example:</p>
 * <pre>
 * {@code
 * AttributeSyncApiClient client = connectorApiFactory.getAttributeApiClient(connectorDto);
 * client.listAttributeDefinitions(connectorDto, functionGroup, kind);
 * }
 * </pre>
 */
@Slf4j
@Component
@RequiredArgsConstructor
public class ConnectorApiFactory {

    // REST clients (always available)
    private final AttributeApiClient restAttributeApiClient;
    private final AuthorityInstanceApiClient restAuthorityInstanceApiClient;
    private final CertificateApiClient restCertificateApiClient;
    private final ConnectorApiClient restConnectorApiClient;
    private final DiscoveryApiClient restDiscoveryApiClient;
    private final EndEntityApiClient restEndEntityApiClient;
    private final EndEntityProfileApiClient restEndEntityProfileApiClient;
    private final EntityInstanceApiClient restEntityInstanceApiClient;
    private final HealthApiClient restHealthApiClient;
    private final LocationApiClient restLocationApiClient;
    private final NotificationInstanceApiClient restNotificationInstanceApiClient;
    private final TokenInstanceApiClient restTokenInstanceApiClient;
    private final KeyManagementApiClient restKeyManagementApiClient;
    private final CryptographicOperationsApiClient restCryptographicOperationsApiClient;
    private final com.otilm.api.clients.v2.AttributesApiClient restAttributesApiClientV2;
    private final com.otilm.api.clients.v2.CertificateApiClient restCertificateApiClientV2;
    private final ComplianceApiClient restComplianceApiClient;
    private final com.otilm.api.clients.v2.ComplianceApiClient restComplianceApiClientV2;
    private final com.otilm.api.clients.v2.HealthApiClient restHealthApiClientV2;
    private final com.otilm.api.clients.v2.InfoApiClient restInfoApiClientV2;
    private final com.otilm.api.clients.v2.MetricsApiClient restMetricsApiClientV2;
    private final com.otilm.api.clients.v3.CertificateApiClient restCertificateApiClientV3;
    private final com.otilm.api.clients.v3.AuthorityApiClient restAuthorityApiClientV3;

    // MQ clients (optional - Spring injects Optional.empty() if bean is missing)
    private final Optional<com.otilm.api.clients.mq.AttributeApiClient> mqAttributeApiClient;
    private final Optional<com.otilm.api.clients.mq.AuthorityInstanceApiClient> mqAuthorityInstanceApiClient;
    private final Optional<com.otilm.api.clients.mq.CertificateApiClient> mqCertificateApiClient;
    private final Optional<com.otilm.api.clients.mq.ConnectorApiClient> mqConnectorApiClient;
    private final Optional<com.otilm.api.clients.mq.DiscoveryApiClient> mqDiscoveryApiClient;
    private final Optional<com.otilm.api.clients.mq.EndEntityApiClient> mqEndEntityApiClient;
    private final Optional<com.otilm.api.clients.mq.EndEntityProfileApiClient> mqEndEntityProfileApiClient;
    private final Optional<com.otilm.api.clients.mq.EntityInstanceApiClient> mqEntityInstanceApiClient;
    private final Optional<com.otilm.api.clients.mq.HealthApiClient> mqHealthApiClient;
    private final Optional<com.otilm.api.clients.mq.LocationApiClient> mqLocationApiClient;
    private final Optional<com.otilm.api.clients.mq.NotificationInstanceApiClient> mqNotificationInstanceApiClient;
    private final Optional<com.otilm.api.clients.mq.TokenInstanceApiClient> mqTokenInstanceApiClient;
    private final Optional<com.otilm.api.clients.mq.KeyManagementApiClient> mqKeyManagementApiClient;
    private final Optional<com.otilm.api.clients.mq.CryptographicOperationsApiClient> mqCryptographicOperationsApiClient;
    private final Optional<com.otilm.api.clients.mq.v2.AttributesApiClient> mqAttributesApiClientV2;
    private final Optional<com.otilm.api.clients.mq.v2.CertificateApiClient> mqCertificateApiClientV2;
    private final Optional<com.otilm.api.clients.mq.ComplianceApiClient> mqComplianceApiClient;
    private final Optional<com.otilm.api.clients.mq.v2.ComplianceApiClient> mqComplianceApiClientV2;
    private final Optional<com.otilm.api.clients.mq.v2.HealthApiClient> mqHealthApiClientV2;
    private final Optional<com.otilm.api.clients.mq.v2.InfoApiClient> mqInfoApiClientV2;
    private final Optional<com.otilm.api.clients.mq.v2.MetricsApiClient> mqMetricsApiClientV2;
    private final Optional<com.otilm.api.clients.mq.v3.CertificateApiClient> mqCertificateApiClientV3;
    private final Optional<com.otilm.api.clients.mq.v3.AuthorityApiClient> mqAuthorityApiClientV3;

    // Signing clients
    private final SignatureFormattingApiClient restSignatureFormattingApiClient;
    private final Optional<com.otilm.api.clients.mq.signing.SignatureFormattingApiClient> mqSignatureFormattingApiClient;

    // Vault/Secret clients
    private final com.otilm.api.clients.secret.VaultApiClient restVaultApiClient;
    private final Optional<com.otilm.api.clients.mq.secret.VaultApiClient> mqVaultApiClient;
    private final com.otilm.api.clients.secret.SecretApiClient restSecretApiClient;

    private ConnectorInternalService connectorService;

    @Autowired
    public void setConnectorService(@Lazy ConnectorInternalService connectorService) {
        this.connectorService = connectorService;
    }

    @PostConstruct
    void logInitialization() {
        log.info("ConnectorApiFactory initialized. MQ clients available: attribute={}, attributesV2={}, authorityInstance={}, certificate={}, certificateV2={}, certificateV3={}, authorityV3={}, compliance={}, complianceV2={}, connector={}, discovery={}, endEntity={}, endEntityProfile={}, entityInstance={}, health={}, healthV2={}, infoV2={}, location={}, metricsV2={}, notificationInstance={}, tokenInstance={}, keyManagement={}, cryptographicOperations={}, signatureFormatting={}, vault={}, secret(REST-only)={}",
                mqAttributeApiClient.isPresent(), mqAttributesApiClientV2.isPresent(), mqAuthorityInstanceApiClient.isPresent(), mqCertificateApiClient.isPresent(), mqCertificateApiClientV2.isPresent(), mqCertificateApiClientV3.isPresent(), mqAuthorityApiClientV3.isPresent(), mqComplianceApiClient.isPresent(), mqComplianceApiClientV2.isPresent(), mqConnectorApiClient.isPresent(), mqDiscoveryApiClient.isPresent(), mqEndEntityApiClient.isPresent(), mqEndEntityProfileApiClient.isPresent(), mqEntityInstanceApiClient.isPresent(), mqHealthApiClient.isPresent(), mqHealthApiClientV2.isPresent(), mqInfoApiClientV2.isPresent(), mqLocationApiClient.isPresent(), mqMetricsApiClientV2.isPresent(), mqNotificationInstanceApiClient.isPresent(), mqTokenInstanceApiClient.isPresent(), mqKeyManagementApiClient.isPresent(), mqCryptographicOperationsApiClient.isPresent(), mqSignatureFormattingApiClient.isPresent(), mqVaultApiClient.isPresent(), true);
    }

    /**
     * Selects between REST and MQ client based on proxy configuration.
     */
    private <T> T getClient(ProxyDto proxy, String connectorName, T restClient, Optional<? extends T> mqClient) {
        if (shouldUseMq(proxy) && mqClient.isPresent()) {
            log.debug("Using MQ client for connector {} via proxy {}", connectorName, proxy.getCode());
            return mqClient.get();
        }
        return restClient;
    }

    private <T> T getClient(ApiClientConnectorInfo connector, T restClient, Optional<? extends T> mqClient) {
        Objects.requireNonNull(connector, "connector must not be null");
        return getClient(connector.getProxy(), connector.getName(), restClient, mqClient);
    }

    public AttributeSyncApiClient getAttributeApiClient(ApiClientConnectorInfo connector) {
        return getClient(connector, restAttributeApiClient, mqAttributeApiClient);
    }

    public ConnectorSyncApiClient getConnectorApiClient(ApiClientConnectorInfo connector) {
        return getClient(connector, restConnectorApiClient, mqConnectorApiClient);
    }

    public com.otilm.api.interfaces.client.v1.HealthSyncApiClient getHealthApiClient(ApiClientConnectorInfo connector) {
        return getClient(connector, restHealthApiClient, mqHealthApiClient);
    }

    public DiscoverySyncApiClient getDiscoveryApiClient(ApiClientConnectorInfo connector) {
        return getClient(connector, restDiscoveryApiClient, mqDiscoveryApiClient);
    }

    public EndEntityProfileSyncApiClient getEndEntityProfileApiClient(ApiClientConnectorInfo connector) {
        return getClient(connector, restEndEntityProfileApiClient, mqEndEntityProfileApiClient);
    }

    public com.otilm.api.interfaces.client.v1.CertificateSyncApiClient getCertificateApiClient(ApiClientConnectorInfo connector) {
        return getClient(connector, restCertificateApiClient, mqCertificateApiClient);
    }

    public AuthorityInstanceSyncApiClient getAuthorityInstanceApiClient(ApiClientConnectorInfo connector) {
        return getClient(connector, restAuthorityInstanceApiClient, mqAuthorityInstanceApiClient);
    }

    public EntityInstanceSyncApiClient getEntityInstanceApiClient(ApiClientConnectorInfo connector) {
        return getClient(connector, restEntityInstanceApiClient, mqEntityInstanceApiClient);
    }

    public LocationSyncApiClient getLocationApiClient(ApiClientConnectorInfo connector) {
        return getClient(connector, restLocationApiClient, mqLocationApiClient);
    }

    public TokenInstanceSyncApiClient getTokenInstanceApiClient(ApiClientConnectorInfo connector) {
        return getClient(connector, restTokenInstanceApiClient, mqTokenInstanceApiClient);
    }

    public KeyManagementSyncApiClient getKeyManagementApiClient(ApiClientConnectorInfo connector) {
        return getClient(connector, restKeyManagementApiClient, mqKeyManagementApiClient);
    }

    public CryptographicOperationsSyncApiClient getCryptographicOperationsApiClient(ApiClientConnectorInfo connector) {
        return getClient(connector, restCryptographicOperationsApiClient, mqCryptographicOperationsApiClient);
    }

    /**
     * UUID-keyed overload for call sites that need to route an API client but never use the connector DTO themselves.
     */
    public CryptographicOperationsSyncApiClient getCryptographicOperationsApiClient(UUID connectorUuid) throws NotFoundException {
        return getCryptographicOperationsApiClient(connectorService.getConnectorForApiClient(connectorUuid));
    }

    public AttributesSyncApiClient getAttributesApiClientV2(ApiClientConnectorInfo connector) {
        return getClient(connector, restAttributesApiClientV2, mqAttributesApiClientV2);
    }

    public CertificateSyncApiClient getCertificateApiClientV2(ApiClientConnectorInfo connector) {
        return getClient(connector, restCertificateApiClientV2, mqCertificateApiClientV2);
    }

    public com.otilm.api.interfaces.client.v1.ComplianceSyncApiClient getComplianceApiClient(ApiClientConnectorInfo connector) {
        return getClient(connector, restComplianceApiClient, mqComplianceApiClient);
    }

    public ComplianceSyncApiClient getComplianceApiClientV2(ApiClientConnectorInfo connector) {
        return getClient(connector, restComplianceApiClientV2, mqComplianceApiClientV2);
    }

    public HealthSyncApiClient getHealthApiClientV2(ApiClientConnectorInfo connector) {
        return getClient(connector, restHealthApiClientV2, mqHealthApiClientV2);
    }

    public InfoSyncApiClient getInfoApiClientV2(ApiClientConnectorInfo connector) {
        return getClient(connector, restInfoApiClientV2, mqInfoApiClientV2);
    }

    public MetricsSyncApiClient getMetricsApiClientV2(ApiClientConnectorInfo connector) {
        return getClient(connector, restMetricsApiClientV2, mqMetricsApiClientV2);
    }

    public EndEntitySyncApiClient getEndEntityApiClient(ApiClientConnectorInfo connector) {
        return getClient(connector, restEndEntityApiClient, mqEndEntityApiClient);
    }

    public NotificationInstanceSyncApiClient getNotificationInstanceApiClient(ApiClientConnectorInfo connector) {
        return getClient(connector, restNotificationInstanceApiClient, mqNotificationInstanceApiClient);
    }

    public SignatureFormattingSyncApiClient getSignatureFormattingApiClient(ApiClientConnectorInfo connector) {
        return getClient(connector, restSignatureFormattingApiClient, mqSignatureFormattingApiClient);
    }

    public com.otilm.api.interfaces.client.v1.secret.VaultSyncApiClient getVaultApiClient(ApiClientConnectorInfo connector) {
        return getClient(connector, restVaultApiClient, mqVaultApiClient);
    }

    public com.otilm.api.clients.secret.SecretApiClient getSecretApiClient(ApiClientConnectorInfo connector) {
        // REST-only — no MQ implementation exists yet
        Objects.requireNonNull(connector, "connector must not be null");
        return restSecretApiClient;
    }

    public com.otilm.api.interfaces.client.v3.CertificateSyncApiClient getCertificateApiClientV3(ApiClientConnectorInfo connector) {
        return getClient(connector, restCertificateApiClientV3, mqCertificateApiClientV3);
    }

    public AuthoritySyncApiClient getAuthorityInstanceApiClientV3(ApiClientConnectorInfo connector) {
        return getClient(connector, restAuthorityApiClientV3, mqAuthorityApiClientV3);
    }

    /**
     * Check if MQ-based communication should be used based on proxy configuration.
     *
     * @param proxy Proxy configuration, may be null
     * @return true if proxy has a non-empty code set
     */
    private boolean shouldUseMq(ProxyDto proxy) {
        return proxy != null && proxy.getCode() != null && !proxy.getCode().isBlank();
    }

}
