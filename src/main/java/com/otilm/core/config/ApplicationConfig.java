package com.otilm.core.config;

import com.otilm.api.clients.AttributeApiClient;
import com.otilm.api.clients.AuthorityInstanceApiClient;
import com.otilm.api.clients.BaseApiClient;
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
import com.otilm.api.clients.SchedulerApiClient;
import com.otilm.api.clients.cryptography.CryptographicOperationsApiClient;
import com.otilm.api.clients.cryptography.KeyManagementApiClient;
import com.otilm.api.clients.cryptography.TokenInstanceApiClient;
import com.otilm.api.clients.secret.SecretApiClient;
import com.otilm.api.clients.secret.VaultApiClient;
import com.otilm.api.clients.signing.SignatureFormattingApiClient;
import com.otilm.api.clients.v2.InfoApiClient;
import com.otilm.api.clients.v2.MetricsApiClient;
import com.otilm.core.security.authn.client.ResourceApiClient;
import com.otilm.core.security.authn.client.RoleManagementApiClient;
import com.otilm.core.security.authn.client.UserManagementApiClient;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.ComponentScan;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Configuration;
import org.springframework.data.domain.AuditorAware;
import org.springframework.data.jpa.repository.config.EnableJpaAuditing;
import org.springframework.web.reactive.function.client.WebClient;

import com.otilm.core.service.DiscoveryProperties;

import javax.net.ssl.TrustManager;

@Configuration
@EnableJpaAuditing(auditorAwareRef = "auditorAware")
@EnableConfigurationProperties(DiscoveryProperties.class)
@ComponentScan(basePackages = "com.otilm.core")
public class ApplicationConfig {

    @Autowired
    private TrustedCertificatesConfig trustedCertificatesConfig;

    // Connectors v2 API Clients

    @Bean(name = "healthApiClientV2")
    public com.otilm.api.clients.v2.HealthApiClient healthApiClientV2(WebClient webClient, TrustManager[] defaultTrustManagers) {
        return new com.otilm.api.clients.v2.HealthApiClient(webClient, defaultTrustManagers);
    }

    @Bean
    public InfoApiClient infoApiClient(WebClient webClient, TrustManager[] defaultTrustManagers) {
        return new InfoApiClient(webClient, defaultTrustManagers);
    }

    @Bean
    public MetricsApiClient metricsApiClient(WebClient webClient, TrustManager[] defaultTrustManagers) {
        return new MetricsApiClient(webClient, defaultTrustManagers);
    }

    @Bean
    public AuditorAware<String> auditorAware() {
        return new CustomAuditAware();
    }

    @Bean
    public WebClient webClient() {
        return BaseApiClient.prepareWebClient();
    }

    @Bean
    public TrustManager[] defaultTrustManagers() {
        return trustedCertificatesConfig.getDefaultTrustManagers();
    }

    @Bean
    public HealthApiClient healthApiClient(WebClient webClient, TrustManager[] defaultTrustManagers) {
        return new HealthApiClient(webClient, defaultTrustManagers);
    }

    @Bean
    public AttributeApiClient attributeApiClient(WebClient webClient, TrustManager[] defaultTrustManagers) {
        return new AttributeApiClient(webClient, defaultTrustManagers);
    }

    @Bean
    public ConnectorApiClient connectorApiClient(WebClient webClient, TrustManager[] defaultTrustManagers) {
        return new ConnectorApiClient(webClient, defaultTrustManagers);
    }

    @Bean
    public AuthorityInstanceApiClient authorityInstanceApiClient(WebClient webClient, TrustManager[] defaultTrustManagers) {
        return new AuthorityInstanceApiClient(webClient, defaultTrustManagers);
    }

    @Bean
    public NotificationInstanceApiClient notificationInstanceApiClient(WebClient webClient, TrustManager[] defaultTrustManagers) {
        return new NotificationInstanceApiClient(webClient, defaultTrustManagers);
    }

    @Bean
    public EntityInstanceApiClient entityInstanceApiClient(WebClient webClient, TrustManager[] defaultTrustManagers) {
        return new EntityInstanceApiClient(webClient, defaultTrustManagers);
    }

    @Bean
    public LocationApiClient locationApiClient(WebClient webClient, TrustManager[] defaultTrustManagers) {
        return new LocationApiClient(webClient, defaultTrustManagers);
    }

    @Bean
    public EndEntityProfileApiClient endEntityProfileApiClient(WebClient webClient, TrustManager[] defaultTrustManagers) {
        return new EndEntityProfileApiClient(webClient, defaultTrustManagers);
    }

    @Bean
    public EndEntityApiClient endEntityApiClient(WebClient webClient, TrustManager[] defaultTrustManagers) {
        return new EndEntityApiClient(webClient, defaultTrustManagers);
    }

    @Bean
    public CertificateApiClient certificateApiClient(WebClient webClient, TrustManager[] defaultTrustManagers) {
        return new CertificateApiClient(webClient, defaultTrustManagers);
    }

    @Bean
    public DiscoveryApiClient discoveryApiClient(WebClient webClient, TrustManager[] defaultTrustManagers) {
        return new DiscoveryApiClient(webClient, defaultTrustManagers);
    }

    @Bean
    public com.otilm.api.clients.v2.CertificateApiClient certificateApiClientV2(WebClient webClient, TrustManager[] defaultTrustManagers) {
        return new com.otilm.api.clients.v2.CertificateApiClient(webClient, defaultTrustManagers);
    }

    @Bean
    public ComplianceApiClient complianceApiClient(WebClient webClient, TrustManager[] defaultTrustManagers) {
        return new ComplianceApiClient(webClient, defaultTrustManagers);
    }

    @Bean
    public com.otilm.api.clients.v2.ComplianceApiClient complianceApiClientV2(WebClient webClient, TrustManager[] defaultTrustManagers) {
        return new com.otilm.api.clients.v2.ComplianceApiClient(webClient, defaultTrustManagers);
    }

    @Bean
    public UserManagementApiClient userManagementApiClient() {
        return new UserManagementApiClient();
    }

    @Bean
    public RoleManagementApiClient roleManagementApiClient() {
        return new RoleManagementApiClient();
    }

    @Bean
    public ResourceApiClient endPointApiClient() {
        return new ResourceApiClient();
    }

    //Cryptographic API Clients
    @Bean
    public TokenInstanceApiClient tokenInstanceApiClient(WebClient webClient, TrustManager[] defaultTrustManagers) {
        return new TokenInstanceApiClient(webClient, defaultTrustManagers);
    }

    @Bean
    public KeyManagementApiClient keyManagementApiClient(WebClient webClient, TrustManager[] defaultTrustManagers) {
        return new KeyManagementApiClient(webClient, defaultTrustManagers);
    }

    @Bean
    public CryptographicOperationsApiClient cryptographicOperationsApiClient(WebClient webClient, TrustManager[] defaultTrustManagers) {
        return new CryptographicOperationsApiClient(webClient, defaultTrustManagers);
    }

    @Bean
    public VaultApiClient vaultApiClient(WebClient webClient, TrustManager[] defaultTrustManagers) {
        return new VaultApiClient(webClient, defaultTrustManagers);
    }

    @Bean
    public SecretApiClient secretApiClient(WebClient webClient, TrustManager[] defaultTrustManagers) {
        return new SecretApiClient(webClient, defaultTrustManagers);
    }

    @Bean
    public SchedulerApiClient schedulerApiClient() {
        return new SchedulerApiClient();
    }

    // Connectors v3 API Clients

    @Bean
    public com.otilm.api.clients.v3.CertificateApiClient certificateApiClientV3(WebClient webClient, TrustManager[] defaultTrustManagers) {
        return new com.otilm.api.clients.v3.CertificateApiClient(webClient, defaultTrustManagers);
    }

    @Bean
    public com.otilm.api.clients.v3.AuthorityApiClient authorityApiClientV3(WebClient webClient, TrustManager[] defaultTrustManagers) {
        return new com.otilm.api.clients.v3.AuthorityApiClient(webClient, defaultTrustManagers);
    }

    @Bean
    public SignatureFormattingApiClient signatureFormattingApiClient(WebClient webClient, TrustManager[] defaultTrustManagers) {
        return new SignatureFormattingApiClient(webClient, defaultTrustManagers);
    }
}
