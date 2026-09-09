package com.otilm.core.cbom.client;

import com.otilm.api.exception.CbomRepositoryException;
import com.otilm.api.model.core.cbom.CbomUploadRequestDto;
import com.otilm.api.model.core.settings.PlatformSettingsDto;
import com.otilm.api.model.core.settings.SettingsSection;
import com.otilm.core.config.CbomSyncProperties;
import com.otilm.core.model.cbom.BomCreateResponseDto;
import com.otilm.core.model.cbom.BomEntryDto;
import com.otilm.core.model.cbom.BomResponseDto;
import com.otilm.core.model.cbom.BomSearchRequestDto;
import com.otilm.core.model.cbom.BomVersionDto;
import com.otilm.core.settings.SettingsCache;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Optional;
import java.util.function.Function;
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
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Component;
import org.springframework.web.reactive.function.client.ClientResponse;
import org.springframework.web.reactive.function.client.ExchangeFilterFunction;
import org.springframework.web.reactive.function.client.WebClient;
import org.springframework.web.reactive.function.client.WebClientRequestException;
import org.springframework.web.reactive.function.client.WebClientResponseException;
import org.springframework.web.util.UriComponentsBuilder;
import reactor.core.Exceptions;
import reactor.core.publisher.Mono;

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
        this.client = client
                .mutate()
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
                .block()
                .getBody(), request);
    }

    /** The last path segment of {@link #CBOM_SEARCH}; a Link target may name it or leave the path empty. */
    private static final String SEARCH_SEGMENT = "bom";

    /** How much of an unusable Link target is quoted in the Core log. */
    private static final int LINK_TARGET_ECHO_LIMIT = 200;

    /**
     * Opens a search run: documents created strictly after {@code query.after} (null reads as 0), the first page when
     * {@code query.limit} is set, the whole unpaged legacy listing when it is not. Follow pages with
     * {@link #nextPage(BomSearchPage)} until {@link BomSearchPage#hasNext()} is false; the absence of the repository's
     * {@code Link rel="next"} header -- not the page size -- says the run is complete.
     */
    public BomSearchPage search(final BomSearchRequestDto query) throws CbomRepositoryException {
        final Integer limit = query.getLimit();
        if (limit != null && (limit < CbomSyncProperties.MIN_PAGE_SIZE || limit > CbomSyncProperties.MAX_PAGE_SIZE)) {
            throw new IllegalArgumentException("CBOM Repository search limit must be within %d..%d, was %d"
                    .formatted(CbomSyncProperties.MIN_PAGE_SIZE, CbomSyncProperties.MAX_PAGE_SIZE, limit));
        }
        final String baseUrl = getCbomRepositoryBaseUrl();
        final UriComponentsBuilder builder = UriComponentsBuilder
                .fromUriString(baseUrl)
                .path(CBOM_SEARCH)
                .queryParam("after", query.getAfter() == null ? 0L : query.getAfter());
        if (limit != null) {
            builder.queryParam("limit", limit);
        }
        return fetchPage(builder.build().toUri());
    }

    /** Fetches the page a previous page's {@code Link rel="next"} header pointed at. */
    public BomSearchPage nextPage(final BomSearchPage page) throws CbomRepositoryException {
        if (!page.hasNext()) {
            throw new IllegalArgumentException("The page carries no next link; the run is complete");
        }
        return fetchPage(page.nextPage());
    }

    private BomSearchPage fetchPage(final URI pageUri) throws CbomRepositoryException {
        final WebClient.RequestBodyUriSpec request = client.method(HttpMethod.GET);
        final ResponseEntity<List<BomEntryDto>> response;
        try {
            response = processRequest(
                    r -> r.uri(pageUri).retrieve().toEntity(new ParameterizedTypeReference<List<BomEntryDto>>() {
                    }).block(), request);
        } catch (CbomRepositoryException e) {
            throw pageRequestFailed(e);
        }
        final Optional<String> target = LinkHeader.nextTarget(response.getHeaders().get(HttpHeaders.LINK));
        final URI next = target.isPresent() ? resolveNextPage(pageUri, target.get()) : null;
        return new BomSearchPage(response.getBody(), next);
    }

    /**
     * A failed page request keeps its status -- the sync run classifies a 503 by it, and any other status fails the run
     * -- but not the repository's own {@code detail}: a failed page fails the whole run, whose message an operator
     * reads in the scheduler's job result, and that sentence is chosen by the other side. It is logged for the Core log
     * and replaced here with Core's own.
     */
    private static CbomRepositoryException pageRequestFailed(final CbomRepositoryException failure) {
        final ProblemDetail reported = failure.getProblemDetail();
        if (reported == null) {
            return failure;
        }
        logger
                .warn("CBOM Repository failed a page request with HTTP {}: {}", reported.getStatus(),
                        reported.getDetail());
        final ProblemDetail shaped = ProblemDetail.forStatus(reported.getStatus());
        shaped.setDetail("CBOM Repository failed a page request (HTTP " + reported.getStatus() + ")");
        return new CbomRepositoryException(shaped);
    }

    /**
     * The repository sends the next page as a relative-path reference, {@code bom?cursor=..&limit=..}. Only its query
     * is used: it is appended to the URL that was just requested, so the host, the mount prefix and any path an ingress
     * rewrites stay Core's own -- the README names this as the way for a client that builds URLs from a configured
     * base. An absolute or path-absolute target, a path other than the search segment, a target without a query, or a
     * query that names {@code after} (the contract forbids combining a cursor with it) means the contract changed under
     * Core; the run fails rather than following it.
     */
    static URI resolveNextPage(final URI requested, final String target) throws CbomRepositoryException {
        final URI reference;
        try {
            reference = new URI(target);
        } catch (URISyntaxException e) {
            throw unusableLink(target);
        }
        final boolean relativeToSearch = reference.getScheme() == null && reference.getRawAuthority() == null
                && !reference.getRawSchemeSpecificPart().startsWith("//")
                && (reference.getRawPath().isEmpty() || SEARCH_SEGMENT.equals(reference.getRawPath()));
        if (!relativeToSearch || StringUtils.isBlank(reference.getRawQuery())
                || namesAfterParameter(reference.getRawQuery())) {
            throw unusableLink(target);
        }
        // The cursor is opaque and may itself carry characters such as the '=' of base64 padding. Decomposing the
        // query into name/value pairs -- as UriComponentsBuilder#replaceQuery followed by build(true) does, to
        // validate each value against Type.QUERY_PARAM -- rejects such a legal value with an unchecked
        // IllegalArgumentException instead of the 502 below. Appending the raw query verbatim to the request URL's
        // own base (its query stripped) keeps the token exactly as the repository sent it.
        final String base = UriComponentsBuilder.fromUri(requested).replaceQuery(null).build(true).toUriString();
        final URI next;
        try {
            next = URI.create(base + "?" + reference.getRawQuery());
        } catch (IllegalArgumentException e) {
            throw unusableLink(target);
        }
        if (next.equals(requested)) {
            throw new CbomRepositoryException(ProblemDetail
                    .forStatusAndDetail(HttpStatus.BAD_GATEWAY, "CBOM Repository repeated the page cursor"));
        }
        return next;
    }

    /**
     * The contract forbids combining a cursor with {@code after}; a Link that does anyway is not safe to follow. The
     * name is compared decoded, because the server decodes it before it reads it: {@code %61fter} is {@code after}, and
     * comparing the raw text would let a target carry the parameter past this guard. The escapes are already known to
     * be well formed -- the target parsed as a URI, which rejects the rest.
     */
    private static boolean namesAfterParameter(final String rawQuery) {
        for (final String pair : rawQuery.split("&")) {
            final int equals = pair.indexOf('=');
            final String rawName = equals >= 0 ? pair.substring(0, equals) : pair;
            if ("after".equals(URLDecoder.decode(rawName, StandardCharsets.UTF_8))) {
                return true;
            }
        }
        return false;
    }

    /**
     * The target goes to the Core log, not into the detail: it is server-supplied text of unbounded length, an absolute
     * one names the repository's own host and mount path, and the detail reaches more than the scheduler's job result
     * -- the sync endpoint's REST caller gets it through the error advice too. Only its first
     * {@value #LINK_TARGET_ECHO_LIMIT} characters are logged.
     */
    private static CbomRepositoryException unusableLink(final String target) {
        if (logger.isWarnEnabled()) {
            logger
                    .warn("CBOM Repository returned an unusable Link header for the next page: {}",
                            StringUtils.abbreviate(target, LINK_TARGET_ECHO_LIMIT));
        }
        return new CbomRepositoryException(ProblemDetail
                .forStatusAndDetail(HttpStatus.BAD_GATEWAY,
                        "CBOM Repository returned an unusable Link header for the next page"));
    }

    public BomResponseDto read(final String urn, final Integer version) throws CbomRepositoryException {
        final WebClient.RequestBodyUriSpec request = client.method(HttpMethod.GET);
        final String baseUrl = getCbomRepositoryBaseUrl();
        return processRequest(r -> r.uri(uriBuilder -> {
            UriComponentsBuilder builder = UriComponentsBuilder.fromUriString(baseUrl).path(CBOM_READ);
            if (version != null) {
                builder.queryParam("version", version);
            }
            return builder.buildAndExpand(urn).toUri();
        }).retrieve().toEntity(BomResponseDto.class).block().getBody(), request);
    }

    public List<BomVersionDto> versions(final String urn) throws CbomRepositoryException {
        final WebClient.RequestBodyUriSpec request = prepareRequest(HttpMethod.GET);
        final String baseUrl = getCbomRepositoryBaseUrl();
        return processRequest(r -> r
                .uri(baseUrl + CBOM_READ_VERSIONS, urn)
                .retrieve()
                .toEntity(new ParameterizedTypeReference<List<BomVersionDto>>() {
                })
                .block()
                .getBody(), request);
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
            throw new CbomRepositoryException(ProblemDetail
                    .forStatusAndDetail(HttpStatus.SERVICE_UNAVAILABLE, "CBOM Repository base URL is not configured"));
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
                throw new CbomRepositoryException(ProblemDetail
                        .forStatusAndDetail(HttpStatus.SERVICE_UNAVAILABLE,
                                "Unable to connect to CBOM Repository: please make sure service is accessible and running."));
            }
            if (unwrappedCause instanceof WebClientResponseException wcre) {
                throw new CbomRepositoryException(ProblemDetail.forStatus(wcre.getStatusCode()));
            }
            throw e;
        }
    }

    public static Mono<ClientResponse> handleHttpExceptions(final ClientResponse clientResponse) {
        if (clientResponse.statusCode().isError()) {
            return clientResponse.bodyToMono(ProblemDetail.class).flatMap(problemDetail -> {
                // The response's status is the one the callers classify by, not whatever the body says: a body
                // that is JSON but no problem detail decodes with status 0, and a body may name another status.
                problemDetail.setStatus(clientResponse.statusCode().value());
                return Mono.<ClientResponse>error(new CbomRepositoryException(problemDetail));
            }).switchIfEmpty(Mono.defer(() -> {
                ProblemDetail pd = ProblemDetail.forStatus(clientResponse.statusCode());
                return Mono.error(new CbomRepositoryException(pd));
            })).onErrorResume(e -> {
                if (e instanceof CbomRepositoryException) {
                    return Mono.error(e);
                }
                return Mono.error(new CbomRepositoryException(ProblemDetail.forStatus(clientResponse.statusCode())));
            });
        }
        return Mono.just(clientResponse);
    }
}
