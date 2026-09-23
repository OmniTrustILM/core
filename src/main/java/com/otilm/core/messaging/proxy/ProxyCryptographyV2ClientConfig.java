package com.otilm.core.messaging.proxy;

import com.otilm.api.clients.mq.ProxyClient;
import com.otilm.api.clients.mq.v2.CryptographicOperationsApiClient;
import com.otilm.api.model.connector.cryptography.v2.OperationResponseValidator;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

/** MQ clients of the cryptography provider v2 API whose simple names collide with their v1 counterparts. */
@Configuration
@ConditionalOnProperty(name = "proxy.enabled", havingValue = "true")
public class ProxyCryptographyV2ClientConfig {

    @Bean
    public CryptographicOperationsApiClient mqCryptographicOperationsApiClientV2(ProxyClient proxyClient,
            OperationResponseValidator responseValidator) {
        return new CryptographicOperationsApiClient(proxyClient, responseValidator);
    }
}
