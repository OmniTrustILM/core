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

class PlatformAuthenticationClientCertificateTest {
    private static final String SUCCESS = "{\"authenticated\":true,\"data\":{\"user\":{\"uuid\":\"00000000-0000-0000-0000-000000000001\",\"username\":\"alice\"},\"roles\":[]}}";
    private MockWebServer server;
    private PlatformAuthenticationClient client;
    private CaffeineCacheManager cacheManager;
    private PlatformAuthenticationCache cache;
    private final AtomicLong ticker = new AtomicLong();
    private final ObjectMapper mapper = new ObjectMapper();

    @BeforeEach
    void setUp() throws Exception {
        server = new MockWebServer();
        server.start();
        cacheManager = new CaffeineCacheManager(CacheConfig.CERTIFICATE_AUTH_CACHE, CacheConfig.TOKEN_AUTH_CACHE,
                CacheConfig.SYSTEM_USER_AUTH_CACHE, CacheConfig.USER_UUID_AUTH_CACHE);
        cacheManager.setCaffeine(Caffeine.newBuilder().expireAfterWrite(5, TimeUnit.MINUTES).ticker(ticker::get));
        cache = new PlatformAuthenticationCache(cacheManager, new TokenJtiIndex(), new UserCertificateIndex());
        client = client();
        MDC.clear();
    }

    private PlatformAuthenticationClient client() {
        return new PlatformAuthenticationClient(mock(AuditLogInternalService.class), mapper, cache,
                server.url("/").toString());
    }

    @AfterEach
    void tearDown() throws Exception {
        server.shutdown();
        MDC.clear();
    }

    @ParameterizedTest
    @MethodSource("com.otilm.core.security.authn.ForwardedCertificateFixtures#supportedHeaders")
    void cacheMissSendsCanonicalLeafToAuth(String header, String content, String thumbprint) throws Exception {
        respond(SUCCESS);
        var certificate = ForwardedClientCertificateParser.parse(header);
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

    @ParameterizedTest
    @MethodSource("com.otilm.core.security.authn.ForwardedCertificateFixtures#malformedHeaders")
    void directAuthenticationRejectsMalformedCertificateBeforeHttp(String header) {
        var failure = assertThrows(PlatformAuthenticationException.class,
                () -> client.authenticate(AuthMethod.CERTIFICATE, header, false));
        assertThat(failure.getMessage()).isEqualTo("Could not parse certificate for authentication.");
        assertThat(server.getRequestCount()).isZero();
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
        client
                .authenticateByCertificate(
                        ForwardedClientCertificateParser.parse("Cert=\"" + pem + "\";Chain=\"" + chain + "\""));
        assertThat(sentBody().get("certificateChain")).isEqualTo(mapper.valueToTree(java.util.List.of(ISSUER_DER)));
    }

    @Test
    void allRepresentationsShareTheSameLeafCacheEntry() throws Exception {
        respond(SUCCESS);
        var original = client.authenticateByCertificate(ForwardedClientCertificateParser.parse(LEAF_DER));
        assertThat(client
                .authenticateByCertificate(
                        ForwardedClientCertificateParser.parse(rfcRequest(":" + ISSUER_DER + ":"), "Custom-Cert")))
                .isSameAs(original);
        String pem = java.net.URLEncoder.encode(LEAF_PEM, java.nio.charset.StandardCharsets.UTF_8).replace("+", "%20");
        assertThat(client.authenticateByCertificate(ForwardedClientCertificateParser.parse("Cert=\"" + pem + "\"")))
                .isSameAs(original);
        assertThat(server.getRequestCount()).isEqualTo(1);
    }

    @Test
    void malformedUnusedCandidateIsRejectedBeforeWarmCacheLookup() throws Exception {
        respond(SUCCESS);
        client.authenticateByCertificate(ForwardedClientCertificateParser.parse(LEAF_DER));
        var request = rfcRequest(":" + ISSUER_DER + ":,:dGVzdA==:");
        assertThrows(IllegalArgumentException.class,
                () -> ForwardedClientCertificateParser.parse(request, "Custom-Cert"));
        assertThat(server.getRequestCount()).isEqualTo(1);
    }

    @Test
    void restRejectsMalformedUnusedCandidateWithAnAlreadyCachedLeaf() throws Exception {
        respond(SUCCESS);
        client.authenticateByCertificate(ForwardedClientCertificateParser.parse(LEAF_DER));
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
    void directStringAuthenticationStillParsesLegacyInput() throws Exception {
        respond(SUCCESS);
        assertThat(client.authenticate(AuthMethod.CERTIFICATE, LEAF_PEM, false).isAnonymous()).isFalse();
        assertThat(sentBody().get("certificateContent").asText()).isEqualTo(LEAF_DER);
    }

    @Test
    void acceptsLegacyShapedAuthSuccessWithoutSendingTrustPolicy() throws Exception {
        respond(SUCCESS);
        var parsed = ForwardedClientCertificateParser.parse(LEAF_DER);
        var info = client.authenticateByCertificate(parsed);
        assertThat(info.isAnonymous()).isFalse();
        assertThat(sentBody().has("certificateTrustPolicy")).isFalse();
        assertThat(client.authenticateByCertificate(parsed)).isSameAs(info);
        assertThat(server.getRequestCount()).isEqualTo(1);
    }

    @Test
    void certificateAndTokenRequestsHaveNoTrustPolicy() throws Exception {
        respond(SUCCESS);
        assertThat(client.authenticate(AuthMethod.CERTIFICATE, LEAF_DER, false).isAnonymous()).isFalse();
        assertThat(sentBody().has("certificateTrustPolicy")).isFalse();
        respond(SUCCESS);
        assertThat(client.authenticate(AuthMethod.TOKEN, Map.of("sub", "alice"), false).isAnonymous()).isFalse();
        var body = sentBody();
        assertThat(body.has("certificateChain")).isFalse();
        assertThat(body.has("certificateTrustPolicy")).isFalse();
    }

    @Test
    void unauthenticatedCertificateResponseRemainsAnonymousAndIsNotCached() throws Exception {
        var parsed = ForwardedClientCertificateParser.parse(LEAF_DER);
        respond("{\"authenticated\":false}");
        assertThat(client.authenticateByCertificate(parsed).isAnonymous()).isTrue();
        assertThat(cacheManager.getCache(CacheConfig.CERTIFICATE_AUTH_CACHE).get(THUMBPRINT)).isNull();
    }

    @Test
    void cachedIdentitySurvivesOnlyRemainingTtlAfterTrustRemovalOrExpiry() throws Exception {
        var parsed = ForwardedClientCertificateParser.parse(LEAF_DER);
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
        var parsed = ForwardedClientCertificateParser.parse(LEAF_DER);
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
}
