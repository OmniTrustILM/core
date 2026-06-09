package com.czertainly.core.cbom.client;

import com.otilm.api.model.core.cbom.CbomUploadRequestDto;
import com.otilm.api.model.core.settings.PlatformSettingsDto;
import com.otilm.api.model.core.settings.SettingsSection;
import com.czertainly.core.model.cbom.BomCreateResponseDto;
import com.czertainly.core.model.cbom.BomEntryDto;
import com.czertainly.core.model.cbom.BomResponseDto;
import com.czertainly.core.model.cbom.BomSearchRequestDto;
import com.czertainly.core.model.cbom.BomVersionDto;
import com.czertainly.core.settings.SettingsCache;
import com.otilm.api.exception.CbomRepositoryException;

import org.apache.commons.lang3.StringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.DependsOn;
import org.springframework.core.ParameterizedTypeReference;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.ProblemDetail;
import org.springframework.stereotype.Component;
import org.springframework.web.reactive.function.client.ClientResponse;
import org.springframework.web.reactive.function.client.ExchangeFilterFunction;
import org.springframework.web.reactive.function.client.WebClient;
import org.springframework.web.reactive.function.client.WebClientRequestException;
import org.springframework.web.reactive.function.client.WebClientResponseException;
import org.springframework.web.util.UriComponentsBuilder;

import reactor.core.Exceptions;
import reactor.core.publisher.Mono;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.function.Function;

@Component
@DependsOn("settingService")
public class CbomRepositoryClient {
    private static final Logger logger = LoggerFactory.getLogger(CbomRepositoryClient.class);

    private static final String CBOM_CREATE = "/api/v1/bom";
    private static final String CBOM_SEARCH = "/api/v1/bom";
    private static final String CBOM_READ = "/api/v1/bom/{urn}";
    private static final String CBOM_READ_VERSIONS = "/api/v1/bom/{urn}/versions";

    private final WebClient client;

    public CbomRepositoryClient(WebClient client, @Value("${cbom.client.max-buffer-size:20971520}") int maxBufferSize) {
        this.client = client.mutate()
        .codecs(configurer -> configurer.defaultCodecs().maxInMemorySize(maxBufferSize))
        .filter(ExchangeFilterFunction.ofResponseProcessor(CbomRepositoryClient::handleHttpExceptions))
        .build();
    }

    public BomCreateResponseDto create(final CbomUploadRequestDto data) throws CbomRepositoryException {
        final WebClient.RequestBodyUriSpec request = prepareRequest(HttpMethod.POST);
        final String baseUrl = getCbomRepositoryBaseUrl();
        return processRequest(r -> r
                        .uri(baseUrl + CBOM_CREATE)
                        .body(Mono.just(data.getContent()), LinkedHashMap.class)
                        .header(HttpHeaders.CONTENT_TYPE, "application/vnd.cyclonedx+json")
                        .retrieve()
                        .toEntity(BomCreateResponseDto.class)
                        .block().getBody(),
                request);
    }

    public List<BomEntryDto> search(final BomSearchRequestDto query) throws CbomRepositoryException {
        String baseUrl = getCbomRepositoryBaseUrl();
        final WebClient.RequestBodyUriSpec request = client.method(HttpMethod.GET);
        return processRequest(r -> r
            .uri(uriBuilder -> UriComponentsBuilder.fromUriString(baseUrl)
                .path(CBOM_SEARCH)
                .queryParam("after", query.getAfter())
                .build()
                .toUri())
            .retrieve()
            .toEntity(new ParameterizedTypeReference<List<BomEntryDto>>() {
            })
            .block().getBody(),
            request);
    }

    public BomResponseDto read(final String urn, final Integer version) throws CbomRepositoryException {
        final WebClient.RequestBodyUriSpec request = client.method(HttpMethod.GET);
        final String baseUrl = getCbomRepositoryBaseUrl();
        return processRequest(r -> r
            .uri(uriBuilder -> {
                UriComponentsBuilder builder = UriComponentsBuilder.fromUriString(baseUrl)
                    .path(CBOM_READ);
                if (version != null) {
                    builder.queryParam("version", version);
                }
                return builder.buildAndExpand(urn).toUri();
            })
            .retrieve()
            .toEntity(BomResponseDto.class)
            .block().getBody(),
            request);
    }

    public List<BomVersionDto> versions(final String urn) throws CbomRepositoryException {
        final WebClient.RequestBodyUriSpec request = prepareRequest(HttpMethod.GET);
        final String baseUrl = getCbomRepositoryBaseUrl();
        return processRequest(r -> r
                        .uri(baseUrl + CBOM_READ_VERSIONS, urn)
                        .retrieve()
                        .toEntity(new ParameterizedTypeReference<List<BomVersionDto>>() {
                        })
                        .block().getBody(),
                request);
    }

    public boolean isConfigured() {
        try {
            return StringUtils.isNotBlank(this.getCbomRepositoryBaseUrl());
        } catch (Exception e) {
            return false;
        }
    }

    private String getCbomRepositoryBaseUrl() throws CbomRepositoryException {
        PlatformSettingsDto platformSettings = SettingsCache.getSettings(SettingsSection.PLATFORM);
        String baseUrl = platformSettings != null && platformSettings.getUtils() != null
        ? platformSettings.getUtils().getCbomRepositoryUrl()
        : null;

        if (StringUtils.isBlank(baseUrl)) {
            throw new CbomRepositoryException(ProblemDetail.forStatusAndDetail(
                HttpStatus.SERVICE_UNAVAILABLE,
                "CBOM Repository base URL is not configured"
            ));
        }
        return baseUrl;
    }

    private WebClient.RequestBodyUriSpec prepareRequest(final HttpMethod method) {
        return client.method(method);
    }

    private static <T, R> R processRequest(Function<T, R> func, T request) throws CbomRepositoryException {
        try {
            return func.apply(request);
        } catch (Exception e) {
            Throwable unwrappedCause = Exceptions.unwrap(e);
            if (unwrappedCause instanceof CbomRepositoryException cbomRepositoryException) {
                throw cbomRepositoryException;
            }
            if (unwrappedCause instanceof WebClientRequestException wcre) {
                logger.error("Unable to connect to CBOM Repository: {}", wcre.getMessage());
                throw new CbomRepositoryException(ProblemDetail.forStatusAndDetail(
                        HttpStatus.SERVICE_UNAVAILABLE,
                        "Unable to connect to CBOM Repository: please make sure service is accessible and running."
                ));
            }
            if (unwrappedCause instanceof WebClientResponseException wcre) {
                throw new CbomRepositoryException(ProblemDetail.forStatus(wcre.getStatusCode()));
            }
            throw e;
        }
    }

    public static Mono<ClientResponse> handleHttpExceptions(final ClientResponse clientResponse) {
        if (clientResponse.statusCode().isError()) {
            return clientResponse.bodyToMono(ProblemDetail.class)
                    .flatMap(problemDetail -> Mono.<ClientResponse>error(new CbomRepositoryException(problemDetail)))
                    .switchIfEmpty(Mono.defer(() -> {
                        ProblemDetail pd = ProblemDetail.forStatus(clientResponse.statusCode());
                        return Mono.error(new CbomRepositoryException(pd));
                    }))
                    .onErrorResume(e -> {
                        if (e instanceof CbomRepositoryException) return Mono.error(e);
                        return Mono.error(new CbomRepositoryException(ProblemDetail.forStatus(clientResponse.statusCode())));
                    });
        }
        return Mono.just(clientResponse);
    }
}
