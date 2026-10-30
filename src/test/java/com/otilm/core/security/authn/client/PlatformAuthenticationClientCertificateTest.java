package com.otilm.core.security.authn.client;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.github.benmanes.caffeine.cache.Caffeine;
import com.otilm.api.model.core.logging.enums.AuthMethod;
import com.otilm.core.config.cache.CacheConfig;
import com.otilm.core.security.authn.ForwardedClientCertificateParser;
import com.otilm.core.security.authn.PlatformAuthenticationException;
import com.otilm.core.service.AuditLogInternalService;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicLong;
import okhttp3.mockwebserver.MockResponse;
import okhttp3.mockwebserver.MockWebServer;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;
import org.slf4j.MDC;
import org.springframework.cache.caffeine.CaffeineCacheManager;
import org.springframework.mock.web.MockHttpServletRequest;

import static com.otilm.core.security.authn.ForwardedCertificateFixtures.ISSUER_DER;
import static com.otilm.core.security.authn.ForwardedCertificateFixtures.LEAF_DER;
import static com.otilm.core.security.authn.ForwardedCertificateFixtures.LEAF_PEM;
import static com.otilm.core.security.authn.ForwardedCertificateFixtures.THUMBPRINT;
import static com.otilm.core.security.authn.ForwardedCertificateFixtures.read;
import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;

class PlatformAuthenticationClientCertificateTest {
    private static final String SUCCESS = "{\"authenticated\":true,\"data\":{\"user\":{\"uuid\":\"00000000-0000-0000-0000-000000000001\",\"username\":\"alice\"},\"roles\":[]}}";
    private MockWebServer server;
    private PlatformAuthenticationClient client;
    private CaffeineCacheManager cacheManager;
    private PlatformAuthenticationCache cache;
    private final AtomicLong ticker = new AtomicLong();
    private final ObjectMapper mapper = new ObjectMapper();
    private AuditLogInternalService auditLogService;

    @BeforeEach
    void setUp() throws Exception {
        server = new MockWebServer();
        server.start();
        cacheManager = new CaffeineCacheManager(CacheConfig.CERTIFICATE_AUTH_CACHE, CacheConfig.TOKEN_AUTH_CACHE,
                CacheConfig.SYSTEM_USER_AUTH_CACHE, CacheConfig.USER_UUID_AUTH_CACHE);
        cacheManager.setCaffeine(Caffeine.newBuilder().expireAfterWrite(5, TimeUnit.MINUTES).ticker(ticker::get));
        cache = new PlatformAuthenticationCache(cacheManager, new TokenJtiIndex(), new UserCertificateIndex());
        auditLogService = mock(AuditLogInternalService.class);
        client = client();
        MDC.clear();
    }

    private PlatformAuthenticationClient client() {
        return new PlatformAuthenticationClient(auditLogService, mapper, cache, server.url("/").toString());
    }

    @AfterEach
    void tearDown() throws Exception {
        server.shutdown();
        MDC.clear();
    }

    @ParameterizedTest
    @MethodSource({
            "com.otilm.core.security.authn.ForwardedCertificateFixtures#supportedHeaders",
            "com.otilm.core.security.authn.ForwardedCertificateFixtures#noncanonicalSingletonHeaders"})
    void cacheMissSendsParsedLeafToAuth(String header, String content, String thumbprint) throws Exception {
        respond(SUCCESS);
        var certificate = parsedCertificate(header);
        var authInfo = client.authenticateByCertificate(certificate);
        var body = sentBody();
        assertThat(body.get("certificateContent").asText()).isEqualTo(content);
        if (certificate.chain().isEmpty()) {
            assertThat(body.has("certificateChain")).isFalse();
        } else {
            assertThat(body.get("certificateChain")).isEqualTo(mapper.valueToTree(certificate.chain()));
        }
        assertThat(body.has("certificateTrustPolicy")).isFalse();
        assertThat(cacheManager.getCache(CacheConfig.CERTIFICATE_AUTH_CACHE).get(thumbprint).get()).isSameAs(authInfo);
        assertThat(client.authenticateByCertificate(certificate)).isSameAs(authInfo);
        assertThat(server.getRequestCount()).isEqualTo(1);
    }

    @Test
    void sendsRfcCompanionCandidatesWithoutTrustPolicy() throws Exception {
        respond(SUCCESS);
        client
                .authenticateByCertificate(
                        ForwardedClientCertificateParser.parse(rfcRequest(":" + ISSUER_DER + ":"), "Custom-Cert"));
        var body = sentBody();
        assertThat(body.get("certificateContent").asText()).isEqualTo(LEAF_DER);
        assertThat(body.get("certificateChain")).isEqualTo(mapper.valueToTree(java.util.List.of(ISSUER_DER)));
        assertThat(body.has("certificateTrustPolicy")).isFalse();
    }

    @Test
    void sendsXfccCandidatesWithoutReparsingTheEnvelope() throws Exception {
        respond(SUCCESS);
        String pem = java.net.URLEncoder.encode(LEAF_PEM, java.nio.charset.StandardCharsets.UTF_8).replace("+", "%20");
        String chain = java.net.URLEncoder
                .encode(LEAF_PEM + read("issuer.pem"), java.nio.charset.StandardCharsets.UTF_8)
                .replace("+", "%20");
        client.authenticateByCertificate(parsedCertificate("Cert=\"" + pem + "\";Chain=\"" + chain + "\""));
        assertThat(sentBody().get("certificateChain")).isEqualTo(mapper.valueToTree(java.util.List.of(ISSUER_DER)));
    }

    @Test
    void allRepresentationsShareTheSameLeafCacheEntry() throws Exception {
        respond(SUCCESS);
        var original = client.authenticateByCertificate(parsedCertificate(LEAF_DER));
        assertThat(client
                .authenticateByCertificate(
                        ForwardedClientCertificateParser.parse(rfcRequest(":" + ISSUER_DER + ":"), "Custom-Cert")))
                .isSameAs(original);
        String pem = java.net.URLEncoder.encode(LEAF_PEM, java.nio.charset.StandardCharsets.UTF_8).replace("+", "%20");
        assertThat(client.authenticateByCertificate(parsedCertificate("Cert=\"" + pem + "\""))).isSameAs(original);
        assertThat(server.getRequestCount()).isEqualTo(1);
    }

    @Test
    void malformedUnusedCandidateIsRejectedBeforeWarmCacheLookup() throws Exception {
        respond(SUCCESS);
        client.authenticateByCertificate(parsedCertificate(LEAF_DER));
        var request = rfcRequest(":" + ISSUER_DER + ":,:dGVzdA==:");
        assertThrows(IllegalArgumentException.class,
                () -> ForwardedClientCertificateParser.parse(request, "Custom-Cert"));
        assertThat(server.getRequestCount()).isEqualTo(1);
    }

    @Test
    void restRejectsMalformedUnusedCandidateWithAnAlreadyCachedLeaf() throws Exception {
        respond(SUCCESS);
        client.authenticateByCertificate(parsedCertificate(LEAF_DER));
        var request = rfcRequest(":" + ISSUER_DER + ":,:dGVzdA==:");
        request.setRequestURI("/v1/auth/profile");
        var response = new org.springframework.mock.web.MockHttpServletResponse();
        org.springframework.security.core.context.SecurityContextHolder.clearContext();
        try {
            new com.otilm.core.security.authn.PlatformAuthenticationFilter(client, "Custom-Cert", "")
                    .doFilter(request, response, new org.springframework.mock.web.MockFilterChain());
            assertThat(org.springframework.security.core.context.SecurityContextHolder.getContext().getAuthentication())
                    .isNull();
            assertThat(server.getRequestCount()).isEqualTo(1);
        } finally {
            org.springframework.security.core.context.SecurityContextHolder.clearContext();
        }
    }

    @Test
    void directStringAuthenticationIsRejectedBeforeHttp() {
        respond(SUCCESS);
        var failure = assertThrows(PlatformAuthenticationException.class,
                () -> client.authenticate(AuthMethod.CERTIFICATE, LEAF_PEM, false));
        assertThat(failure.getMessage()).isEqualTo("Parsed certificate identity required.");
        assertThat(server.getRequestCount()).isZero();
    }

    @Test
    void acceptsLegacyShapedAuthSuccessWithoutSendingTrustPolicy() throws Exception {
        respond(SUCCESS);
        var parsed = parsedCertificate(LEAF_DER);
        var info = client.authenticateByCertificate(parsed);
        assertThat(info.isAnonymous()).isFalse();
        assertThat(sentBody().has("certificateTrustPolicy")).isFalse();
        assertThat(client.authenticateByCertificate(parsed)).isSameAs(info);
        assertThat(server.getRequestCount()).isEqualTo(1);
    }

    @Test
    void certificateAndTokenRequestsHaveNoTrustPolicy() throws Exception {
        respond(SUCCESS);
        assertThat(client.authenticate(AuthMethod.CERTIFICATE, parsedCertificate(LEAF_DER), false).isAnonymous())
                .isFalse();
        assertThat(sentBody().has("certificateTrustPolicy")).isFalse();
        respond(SUCCESS);
        assertThat(client.authenticate(AuthMethod.TOKEN, Map.of("sub", "alice"), false).isAnonymous()).isFalse();
        var body = sentBody();
        assertThat(body.has("certificateChain")).isFalse();
        assertThat(body.has("certificateTrustPolicy")).isFalse();
    }

    @Test
    void unauthenticatedCertificateResponseRemainsAnonymousAndIsNotCached() throws Exception {
        var parsed = parsedCertificate(LEAF_DER);
        respond("{\"authenticated\":false}");
        assertThat(client.authenticateByCertificate(parsed).isAnonymous()).isTrue();
        assertThat(cacheManager.getCache(CacheConfig.CERTIFICATE_AUTH_CACHE).get(THUMBPRINT)).isNull();
    }

    @Test
    void cachedIdentitySurvivesOnlyRemainingTtlAfterTrustRemovalOrExpiry() throws Exception {
        var parsed = parsedCertificate(LEAF_DER);
        respond(SUCCESS);
        var info = client.authenticateByCertificate(parsed);
        ticker.set(TimeUnit.MINUTES.toNanos(2));
        // Auth now refuses uncached validation, as after a root removal or certificate expiry.
        respond("{\"authenticated\":false}");
        ticker.set(TimeUnit.MINUTES.toNanos(5) - 1);
        assertThat(client.authenticateByCertificate(parsed)).isSameAs(info);
        assertThat(server.getRequestCount()).isEqualTo(1);
        ticker.incrementAndGet();
        assertThat(client.authenticateByCertificate(parsed).isAnonymous()).isTrue();
        assertThat(server.getRequestCount()).isEqualTo(2);
        respond("{\"authenticated\":false}");
        assertThat(client.authenticateByCertificate(parsed).isAnonymous()).isTrue();
        assertThat(server.getRequestCount()).isEqualTo(3);
        assertThat(cacheManager.getCache(CacheConfig.CERTIFICATE_AUTH_CACHE).get(THUMBPRINT)).isNull();
    }

    @Test
    void userAndFingerprintEvictionRequireFreshAuthentication() throws Exception {
        var parsed = parsedCertificate(LEAF_DER);
        respond(SUCCESS);
        client.authenticateByCertificate(parsed);
        cache.evictByUserUuid(UUID.fromString("00000000-0000-0000-0000-000000000001"));
        respond(SUCCESS);
        client.authenticateByCertificate(parsed);
        cache.evictByCertificateFingerprint(THUMBPRINT);
        respond("{\"authenticated\":false}");
        assertThat(client.authenticateByCertificate(parsed).isAnonymous()).isTrue();
        assertThat(server.getRequestCount()).isEqualTo(3);
        assertThat(cacheManager.getCache(CacheConfig.CERTIFICATE_AUTH_CACHE).get(THUMBPRINT)).isNull();
    }

    private static ForwardedClientCertificateParser.ParsedCertificate parsedCertificate(String header)
            throws Exception {
        var request = new MockHttpServletRequest();
        request.addHeader("Custom-Cert", header);
        return ForwardedClientCertificateParser.parse(request, "Custom-Cert");
    }

    private MockHttpServletRequest rfcRequest(String chain) {
        var request = new MockHttpServletRequest();
        request.addHeader("Custom-Cert", ":" + LEAF_DER + ":");
        request.addHeader("Client-Cert-Chain", chain);
        return request;
    }

    private void respond(String body) {
        server.enqueue(new MockResponse().setHeader("Content-Type", "application/json").setBody(body));
    }

    private com.fasterxml.jackson.databind.JsonNode sentBody() throws Exception {
        var sent = server.takeRequest(5, TimeUnit.SECONDS);
        assertThat(sent).isNotNull();
        assertThat(sent.getPath()).isEqualTo("/auth");
        return mapper.readTree(sent.getBody().readUtf8());
    }

    @Test
    void failureDiagnosticsClassifyServicesWithoutEchoingUncontrolledText() {
        var request = new MockHttpServletRequest();
        request.addHeader("Custom-Cert", "private-submitted-material%%%");
        var invalid = assertThrows(ForwardedClientCertificateParser.InvalidCertificateHeaderException.class,
                () -> ForwardedClientCertificateParser.parse(request, "Custom-Cert"));
        assertThat(PlatformAuthenticationClient.certificateFailureReason(invalid))
                .isEqualTo("Invalid certificate transport encoding");
        var unavailable = new org.springframework.web.reactive.function.client.WebClientRequestException(
                new java.io.IOException("private-upstream-detail"), org.springframework.http.HttpMethod.POST,
                java.net.URI.create("http://localhost/auth"), new org.springframework.http.HttpHeaders());
        var serverError = org.springframework.web.reactive.function.client.WebClientResponseException
                .create(500, "private-upstream-detail", new org.springframework.http.HttpHeaders(), new byte[0], null);
        for (Throwable failure : java.util.List
                .of(unavailable, serverError, new com.otilm.core.security.exception.AuthenticationServiceException(503,
                        "private-upstream-detail"))) {
            assertThat(PlatformAuthenticationClient
                    .certificateFailureReason(new PlatformAuthenticationException("private-wrapper-detail", failure)))
                    .isEqualTo("Authentication service unavailable");
        }
        var missingStatus = new com.otilm.core.security.exception.AuthenticationServiceException(null,
                "private-upstream-detail");
        var missingDetail = new com.otilm.core.security.exception.AuthenticationServiceException(401,
                "private-upstream-detail");
        missingDetail.setException(null);
        for (Throwable failure : java.util.List
                .of(missingStatus, missingDetail, new com.otilm.core.security.exception.AuthenticationServiceException(
                        401, "private-upstream-detail"))) {
            assertThat(PlatformAuthenticationClient.certificateFailureReason(failure))
                    .isEqualTo("Authentication service rejected certificate");
        }
        assertThat(PlatformAuthenticationClient
                .certificateFailureReason(
                        new com.fasterxml.jackson.core.JsonProcessingException("private-parser-detail") {
                        }))
                .isEqualTo("Invalid authentication service response");
        for (Throwable failure : java.util.List
                .of(new IllegalArgumentException("private-submitted-detail"),
                        new PlatformAuthenticationException("private-wrapper-detail"))) {
            assertThat(PlatformAuthenticationClient.certificateFailureReason(failure))
                    .isEqualTo("Certificate authentication failed");
        }
    }

    @ParameterizedTest
    @org.junit.jupiter.params.provider.ValueSource(ints = {204, 401, 503})
    void certificateDebugAndAuditExcludeSubmittedAndUpstreamMaterial(int status) throws Throwable {
        String privateDetail = "private-upstream-material";
        server
                .enqueue(new MockResponse()
                        .setResponseCode(status)
                        .setHeader("Content-Type", "application/json")
                        .setBody(status == 204
                                ? ""
                                : mapper
                                        .writeValueAsString(Map
                                                .of("statusCode", status, "message",
                                                        privateDetail + LEAF_DER + ISSUER_DER))));
        String expected = switch (status) {
            case 204 -> "Empty response received from authentication service";
            case 401 -> "Authentication service rejected certificate";
            default -> "Authentication service unavailable";
        };
        var certificate = parsedCertificate(LEAF_DER + "," + ISSUER_DER);
        var logger = (ch.qos.logback.classic.Logger) org.slf4j.LoggerFactory
                .getLogger(PlatformAuthenticationClient.class);
        var priorLevel = logger.getLevel();
        logger.setLevel(ch.qos.logback.classic.Level.DEBUG);
        try {
            var messages = com.otilm.core.security.authn.ForwardedCertificateFixtures
                    .captureLogs(PlatformAuthenticationClient.class,
                            () -> assertThat(assertThrows(PlatformAuthenticationException.class,
                                    () -> client.authenticateByCertificate(certificate))).hasMessage(expected));
            assertThat(messages)
                    .anyMatch(message -> message.contains(expected))
                    .noneMatch(message -> message.contains(privateDetail) || message.contains(LEAF_DER)
                            || message.contains(ISSUER_DER));
            verify(auditLogService)
                    .logAuthentication(
                            org.mockito.ArgumentMatchers
                                    .eq(com.otilm.api.model.core.logging.enums.Operation.AUTHENTICATION),
                            org.mockito.ArgumentMatchers
                                    .eq(com.otilm.api.model.core.logging.enums.OperationResult.FAILURE),
                            org.mockito.ArgumentMatchers.eq(expected), org.mockito.ArgumentMatchers.isNull());
            var body = sentBody();
            assertThat(body.get("certificateContent").asText()).isEqualTo(LEAF_DER);
            assertThat(body.get("certificateChain")).isEqualTo(mapper.valueToTree(java.util.List.of(ISSUER_DER)));
        } finally {
            logger.setLevel(priorLevel);
        }
    }

    @Test
    void certificateTransportFailureDoesNotExposeDependencyMessageInDebugOrAudit() throws Throwable {
        String privateDetail = "private-dependency-material";
        var failure = new org.springframework.web.reactive.function.client.WebClientRequestException(
                new java.io.IOException(privateDetail), org.springframework.http.HttpMethod.POST,
                java.net.URI.create("http://localhost/" + privateDetail), new org.springframework.http.HttpHeaders());
        client = new PlatformAuthenticationClient(auditLogService, mapper, cache, server.url("/").toString()) {
            @Override
            public org.springframework.web.reactive.function.client.WebClient getClient(String url) {
                throw failure;
            }
        };
        var certificate = parsedCertificate(LEAF_DER);
        var logger = (ch.qos.logback.classic.Logger) client.logger;
        var priorLevel = logger.getLevel();
        logger.setLevel(ch.qos.logback.classic.Level.DEBUG);
        try {
            var messages = com.otilm.core.security.authn.ForwardedCertificateFixtures
                    .captureLogs(client.getClass(),
                            () -> assertThat(assertThrows(PlatformAuthenticationException.class,
                                    () -> client.authenticateByCertificate(certificate)))
                                    .hasMessage("Authentication service unavailable")
                                    .hasCause(failure));
            assertThat(messages)
                    .anyMatch(message -> message.contains("Authentication service unavailable"))
                    .noneMatch(message -> message.contains(privateDetail) || message.contains(LEAF_DER));
            verify(auditLogService)
                    .logAuthentication(
                            org.mockito.ArgumentMatchers
                                    .eq(com.otilm.api.model.core.logging.enums.Operation.AUTHENTICATION),
                            org.mockito.ArgumentMatchers
                                    .eq(com.otilm.api.model.core.logging.enums.OperationResult.FAILURE),
                            org.mockito.ArgumentMatchers.eq("Authentication service unavailable"),
                            org.mockito.ArgumentMatchers.isNull());
            assertThat(server.getRequestCount()).isZero();
        } finally {
            logger.setLevel(priorLevel);
        }
    }
}
