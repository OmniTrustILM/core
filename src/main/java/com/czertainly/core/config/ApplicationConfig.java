package com.czertainly.core.config;

import com.czertainly.api.clients.AttributeApiClient;
import com.czertainly.api.clients.AuthorityInstanceApiClient;
import com.czertainly.api.clients.BaseApiClient;
import com.czertainly.api.clients.CertificateApiClient;
import com.czertainly.api.clients.ComplianceApiClient;
import com.czertainly.api.clients.ConnectorApiClient;
import com.czertainly.api.clients.DiscoveryApiClient;
import com.czertainly.api.clients.EndEntityApiClient;
import com.czertainly.api.clients.EndEntityProfileApiClient;
import com.czertainly.api.clients.EntityInstanceApiClient;
import com.czertainly.api.clients.HealthApiClient;
import com.czertainly.api.clients.LocationApiClient;
import com.czertainly.api.clients.NotificationInstanceApiClient;
import com.czertainly.api.clients.SchedulerApiClient;
import com.czertainly.api.clients.cryptography.CryptographicOperationsApiClient;
import com.czertainly.api.clients.cryptography.KeyManagementApiClient;
import com.czertainly.api.clients.cryptography.TokenInstanceApiClient;
import com.czertainly.api.clients.secret.SecretApiClient;
import com.czertainly.api.clients.secret.VaultApiClient;
import com.czertainly.api.clients.v2.InfoApiClient;
import com.czertainly.api.clients.v2.MetricsApiClient;
import com.czertainly.core.security.authn.client.ResourceApiClient;
import com.czertainly.core.security.authn.client.RoleManagementApiClient;
import com.czertainly.core.security.authn.client.UserManagementApiClient;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.ComponentScan;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.PropertySource;
import org.springframework.data.domain.AuditorAware;
import org.springframework.data.jpa.repository.config.EnableJpaAuditing;
import org.springframework.web.reactive.function.client.WebClient;

import com.czertainly.core.service.DiscoveryProperties;

import javax.net.ssl.TrustManager;

@Configuration
@EnableJpaAuditing(auditorAwareRef = "auditorAware")
@EnableConfigurationProperties(DiscoveryProperties.class)
@PropertySource(value = ApplicationConfig.EXTERNAL_PROPERTY_SOURCE, ignoreResourceNotFound = true)
@ComponentScan(basePackages = "com.czertainly.core")
public class ApplicationConfig {

    @Autowired
    private TrustedCertificatesConfig trustedCertificatesConfig;

    public static final String EXTERNAL_PROPERTY_SOURCE =
            "file:${czertainly-backend.config.dir:/etc/czertainly-backend}/czertainly-backend.properties";


    // Connectors v2 API Clients

    @Bean(name = "healthApiClientV2")
    public com.czertainly.api.clients.v2.HealthApiClient healthApiClientV2(WebClient webClient, TrustManager[] defaultTrustManagers) {
        return new com.czertainly.api.clients.v2.HealthApiClient(webClient, defaultTrustManagers);
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
    public com.czertainly.api.clients.v2.CertificateApiClient certificateApiClientV2(WebClient webClient, TrustManager[] defaultTrustManagers) {
        return new com.czertainly.api.clients.v2.CertificateApiClient(webClient, defaultTrustManagers);
    }

    @Bean
    public ComplianceApiClient complianceApiClient(WebClient webClient, TrustManager[] defaultTrustManagers) {
        return new ComplianceApiClient(webClient, defaultTrustManagers);
    }

    @Bean
    public com.czertainly.api.clients.v2.ComplianceApiClient complianceApiClientV2(WebClient webClient, TrustManager[] defaultTrustManagers) {
        return new com.czertainly.api.clients.v2.ComplianceApiClient(webClient, defaultTrustManagers);
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
}
