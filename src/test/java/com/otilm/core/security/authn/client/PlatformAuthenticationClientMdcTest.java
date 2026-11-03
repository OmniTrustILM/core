package com.otilm.core.security.authn.client;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.otilm.api.model.core.logging.enums.AuthMethod;
import com.otilm.api.model.core.logging.records.DelegateRecord;
import com.otilm.core.logging.LoggingHelper;
import com.otilm.core.security.authn.ForwardedClientCertificateParser;
import com.otilm.core.service.AuditLogInternalService;
import java.util.Map;
import java.util.UUID;
import java.util.stream.Stream;
import okhttp3.mockwebserver.MockResponse;
import okhttp3.mockwebserver.MockWebServer;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Named;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;
import org.slf4j.MDC;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.security.oauth2.jwt.JwtClaimNames;

import static com.otilm.core.security.authn.ForwardedCertificateFixtures.LEAF_DER;
import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Named.named;
import static org.mockito.Mockito.mock;

class PlatformAuthenticationClientMdcTest {

    private static final String CERTIFICATE_HEADER = "Custom-Cert";
    private static final String SYSTEM_USERNAME = "system";
    private static final String UNAUTHENTICATED = "{\"authenticated\":false}";

    private final MockWebServer server = new MockWebServer();
    private PlatformAuthenticationClient client;

    static Stream<Named<Authentication>> authentications() throws Exception {
        UUID userUuid = UUID.randomUUID();
        ForwardedClientCertificateParser.ParsedCertificate certificate = certificate();
        Map<String, Object> claims = Map.of(JwtClaimNames.ISS, "https://issuer.example", JwtClaimNames.JTI, "jti");
        return Stream
                .of(named("as a system user",
                        new Authentication(AuthMethod.USER_PROXY, SYSTEM_USERNAME,
                                client -> client.authenticateSystemUser(SYSTEM_USERNAME))),
                        named("by user UUID",
                                new Authentication(AuthMethod.USER_PROXY, userUuid,
                                        client -> client.authenticateByUserUuid(userUuid))),
                        named("by certificate",
                                new Authentication(AuthMethod.CERTIFICATE, certificate,
                                        client -> client.authenticateByCertificate(certificate))),
                        named("by token", new Authentication(AuthMethod.TOKEN, claims,
                                client -> client.authenticateByToken(claims, 0))));
    }

    @BeforeEach
    void startServer() throws Exception {
        server.start();
        client = new PlatformAuthenticationClient(mock(AuditLogInternalService.class), new ObjectMapper(),
                sharing(AuthenticationInfo.getAnonymousAuthenticationInfo()), server.url("/").toString());
        MDC.clear();
    }

    @AfterEach
    void stopServer() throws Exception {
        server.shutdown();
        MDC.clear();
    }

    @ParameterizedTest
    @MethodSource("authentications")
    void anAnonymousResultAnotherCallerLoadedLeavesTheMdcOfALoad(Authentication authentication) {
        // given — the MDC an anonymous answer of the authentication service leaves on a request holding a delegate
        server.enqueue(new MockResponse().setHeader("Content-Type", "application/json").setBody(UNAUTHENTICATED));
        withDelegate();
        client.authenticate(authentication.method(), authentication.data(), false);
        Map<String, String> afterLoad = MDC.getCopyOfContextMap();
        MDC.clear();
        withDelegate();

        // when
        authentication.lookup().call(client);

        // then
        assertThat(MDC.getCopyOfContextMap()).isEqualTo(afterLoad);
    }

    /** A cache answering every lookup with a result another caller's load produced. */
    private static AuthenticationCache sharing(AuthenticationInfo loadedElsewhere) {
        return mock(AuthenticationCache.class, invocation -> loadedElsewhere);
    }

    private static void withDelegate() {
        LoggingHelper.putDelegateInfo(new DelegateRecord("delegate", "subject"));
    }

    private static ForwardedClientCertificateParser.ParsedCertificate certificate() throws Exception {
        var request = new MockHttpServletRequest();
        request.addHeader(CERTIFICATE_HEADER, LEAF_DER);
        return ForwardedClientCertificateParser.parse(request, CERTIFICATE_HEADER);
    }

    private record Authentication(AuthMethod method, Object data, Lookup lookup) {
    }

    @FunctionalInterface
    private interface Lookup {
        AuthenticationInfo call(PlatformAuthenticationClient client);
    }
}
