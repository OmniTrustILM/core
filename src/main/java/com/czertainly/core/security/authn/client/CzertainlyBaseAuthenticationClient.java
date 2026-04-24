package com.czertainly.core.security.authn.client;

import com.czertainly.api.clients.CzertainlyBaseApiClient;
import com.czertainly.core.security.exception.AuthenticationServiceException;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Component;
import org.springframework.web.reactive.function.client.ClientResponse;
import org.springframework.web.reactive.function.client.WebClient;
import reactor.core.publisher.Mono;

import java.util.function.Function;

@Component
public class CzertainlyBaseAuthenticationClient extends CzertainlyBaseApiClient {

    private static final Log logger = LogFactory.getLog(CzertainlyBaseAuthenticationClient.class);

    @Value("${auth-service.base-url}")
    private String authServiceBaseUrl;

    @Override
    protected String getServiceUrl() {
        return authServiceBaseUrl;
    }

    public CzertainlyBaseAuthenticationClient(String authServiceBaseUrl, WebClient client) {
        this.authServiceBaseUrl = authServiceBaseUrl;
        this.client = client;
    }

    public CzertainlyBaseAuthenticationClient() {
    }

    @Override
    protected Function<ClientResponse, Mono<ClientResponse>> getHttpExceptionHandler() {
        return CzertainlyAuthenticationClient::handleHttpExceptions;
    }

    static Mono<ClientResponse> handleHttpExceptions(ClientResponse clientResponse) {

        if (HttpStatus.INTERNAL_SERVER_ERROR.equals(clientResponse.statusCode())) {
            return clientResponse.bodyToMono(String.class)
                    .flatMap(body -> Mono.error(new AuthenticationServiceException(500, "Internal Server Error from Auth Service")));
        }

        if (clientResponse.statusCode().isError()) {
            return clientResponse.bodyToMono(String.class)
                    .flatMap(body -> Mono.error(new AuthenticationServiceException(body, true)));
        }

        return Mono.just(clientResponse);
    }
}