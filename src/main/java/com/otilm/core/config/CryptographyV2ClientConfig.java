package com.otilm.core.config;

import com.otilm.api.clients.cryptography.v2.CryptographicOperationsApiClient;
import com.otilm.api.model.connector.cryptography.v2.OperationResponseValidator;
import javax.net.ssl.TrustManager;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.reactive.function.client.WebClient;

/** REST clients of the cryptography provider v2 API whose simple names collide with their v1 counterparts. */
@Configuration
public class CryptographyV2ClientConfig {

    @Bean
    public CryptographicOperationsApiClient cryptographicOperationsApiClientV2(WebClient webClient,
            TrustManager[] defaultTrustManagers, OperationResponseValidator responseValidator) {
        return new CryptographicOperationsApiClient(webClient, defaultTrustManagers, responseValidator);
    }
}
