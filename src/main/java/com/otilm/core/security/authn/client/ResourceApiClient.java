package com.otilm.core.security.authn.client;

import com.otilm.api.model.core.auth.AuthResourceDto;
import com.otilm.core.model.auth.ResourceSyncRequestDto;
import com.otilm.core.model.auth.SyncRequestDto;
import com.otilm.core.model.auth.SyncResponseDto;
import org.springframework.core.ParameterizedTypeReference;
import org.springframework.http.HttpMethod;
import org.springframework.web.reactive.function.client.WebClient;
import reactor.core.publisher.Mono;

import java.util.List;

public class ResourceApiClient extends CzertainlyBaseAuthenticationClient {

    private static final ParameterizedTypeReference<List<SyncRequestDto>> ENDPOINT_LIST_TYPE_REF = new ParameterizedTypeReference<>() {
    };

    private static final String RESOURCE_CONTEXT = "/auth/resources";
    private static final String RESOURCE_SYNC_CONTEXT = "/auth/resources/sync";

    public ResourceApiClient(String authServiceBaseUrl, WebClient client) {
        super(authServiceBaseUrl, client);
    }

    public ResourceApiClient() {
    }

    public void addResources(List<ResourceSyncRequestDto> requestDto) {
        WebClient.RequestBodyUriSpec request = prepareRequest(HttpMethod.POST);

        processRequest(r -> r
                        .uri(RESOURCE_CONTEXT)
                        .body(Mono.just(requestDto), ENDPOINT_LIST_TYPE_REF)
                        .retrieve()
                        .toEntity(Void.class)
                        .block().getBody(),
                request);
    }

    public SyncResponseDto syncResources(List<ResourceSyncRequestDto> requestDto) {
        WebClient.RequestBodyUriSpec request = prepareRequest(HttpMethod.POST);

        return processRequest(r -> r
                        .uri(RESOURCE_SYNC_CONTEXT)
                        .body(Mono.just(requestDto), ENDPOINT_LIST_TYPE_REF)
                        .retrieve()
                        .toEntity(SyncResponseDto.class)
                        .block().getBody(),
                request);
    }

    public List<AuthResourceDto> getAuthResources() {
        WebClient.RequestBodyUriSpec request = prepareRequest(HttpMethod.GET);

        return processRequest(r -> r
                        .uri(RESOURCE_CONTEXT)
                        .retrieve()
                        .toEntityList(AuthResourceDto.class)
                        .block().getBody(),
                request);
    }
}
