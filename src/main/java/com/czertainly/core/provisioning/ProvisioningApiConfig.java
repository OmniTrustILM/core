package com.czertainly.core.provisioning;

import lombok.RequiredArgsConstructor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.boot.http.client.ClientHttpRequestFactoryBuilder;
import org.springframework.boot.http.client.ClientHttpRequestFactorySettings;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.client.BufferingClientHttpRequestFactory;
import org.springframework.http.client.ClientHttpRequestFactory;
import org.springframework.http.client.ClientHttpRequestInterceptor;
import org.springframework.http.client.ClientHttpResponse;
import org.springframework.web.client.RestClient;
import org.springframework.web.client.support.RestClientAdapter;
import org.springframework.web.service.invoker.HttpServiceProxyFactory;

import java.nio.charset.StandardCharsets;

/**
 * Configuration for the provisioning API clients.
 */
@Configuration
@EnableConfigurationProperties(ProvisioningApiProperties.class)
@RequiredArgsConstructor
public class ProvisioningApiConfig {

    private final ProvisioningApiProperties provisioningApiProperties;

    @Bean
    public ClientHttpRequestInterceptor provisioningHttpLoggingInterceptor() {
        Logger log = LoggerFactory.getLogger(ProvisioningApiConfig.class.getPackageName() + ".http");
        return (request, body, execution) -> {
            log.info(">>> {} {}", request.getMethod(), request.getURI());
            if (log.isDebugEnabled() && body.length > 0) {
                log.debug(">>> Body: {}", new String(body, StandardCharsets.UTF_8));
            }

            ClientHttpResponse response = execution.execute(request, body);

            log.info("<<< {}", response.getStatusCode());
            if (log.isDebugEnabled()) {
                String responseBody = new String(response.getBody().readAllBytes(), StandardCharsets.UTF_8);
                if (!responseBody.isEmpty()) {
                    log.debug("<<< Body: {}", responseBody);
                }
            }

            return response;
        };
    }

    @Bean
    public RestClient provisioningRestClient(ClientHttpRequestInterceptor provisioningHttpLoggingInterceptor) {
        ClientHttpRequestFactorySettings settings = ClientHttpRequestFactorySettings.defaults()
            .withConnectTimeout(provisioningApiProperties.connectTimeout())
            .withReadTimeout(provisioningApiProperties.readTimeout());

        ClientHttpRequestFactory factory = ClientHttpRequestFactoryBuilder.detect().build(settings);

        return RestClient.builder()
            .baseUrl(provisioningApiProperties.url())
            .requestFactory(new BufferingClientHttpRequestFactory(factory))
            .defaultHeader("X-API-Key", provisioningApiProperties.apiKey())
            .requestInterceptor(provisioningHttpLoggingInterceptor)
            .build();
    }

    @Bean
    public ProxyProvisioningApiClient proxyProvisioningApiClient(RestClient provisioningRestClient) {
        HttpServiceProxyFactory httpServiceProxyFactory = HttpServiceProxyFactory.builderFor(RestClientAdapter.create(provisioningRestClient))
            .build();
        return httpServiceProxyFactory.createClient(ProxyProvisioningApiClient.class);
    }

    @Bean
    public TrustedCertificateProvisioningApiClient trustedCertificateProvisioningApiClient(RestClient provisioningRestClient) {
        HttpServiceProxyFactory httpServiceProxyFactory = HttpServiceProxyFactory.builderFor(RestClientAdapter.create(provisioningRestClient))
            .build();
        return httpServiceProxyFactory.createClient(TrustedCertificateProvisioningApiClient.class);
    }
}