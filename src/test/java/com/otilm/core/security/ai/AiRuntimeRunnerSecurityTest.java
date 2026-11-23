package com.otilm.core.security.ai;

import com.otilm.ai.runtime.protocol.ProtocolCodec;
import com.otilm.ai.runtime.protocol.RuntimeErrorCode;
import com.otilm.core.api.ai.AiRuntimeGatewayController;
import com.otilm.core.api.ai.AiRuntimeManagementGatewayController;
import com.otilm.core.api.ai.AiRuntimeRunnerController;
import com.otilm.core.service.AiRuntimeGatewayExternalService;
import com.otilm.core.service.AiRuntimeManagementGatewayExternalService;
import com.otilm.core.service.AiRuntimeRunnerExternalService;
import jakarta.servlet.DispatcherType;
import jakarta.servlet.Filter;
import java.io.InputStream;
import java.util.UUID;
import java.util.concurrent.atomic.AtomicInteger;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;
import org.junit.jupiter.params.provider.ValueSource;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Import;
import org.springframework.core.annotation.Order;
import org.springframework.http.ResponseEntity;
import org.springframework.mock.web.MockServletContext;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.web.DefaultSecurityFilterChain;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.util.matcher.AnyRequestMatcher;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.web.context.support.AnnotationConfigWebApplicationContext;
import org.springframework.web.servlet.config.annotation.EnableWebMvc;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.verifyNoMoreInteractions;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;

class AiRuntimeRunnerSecurityTest {
    private static final String BOOTSTRAP = "/internal/ai-runtime/v1/runner/bootstrap";
    private static final String HEARTBEAT = "/internal/ai-runtime/v1/runner/claims/heartbeat";
    private static final String REDEEM = "/internal/ai-runtime/v1/gateway/run/redeem";
    private static final String OUTCOME = "/internal/ai-runtime/v1/gateway/run/outcomes";
    private static final String MANAGEMENT_REDEEM = "/internal/ai-management/v1/gateway/redeem";
    private static final String MANAGEMENT_OUTCOME = "/internal/ai-management/v1/gateway/outcomes";
    private final ProtocolCodec codec = new ProtocolCodec();
    private AnnotationConfigWebApplicationContext context;
    private AiRuntimeRunnerExternalService service;
    private AiRuntimeGatewayExternalService gateway;
    private AiRuntimeManagementGatewayExternalService management;
    private AtomicInteger fallback;
    private MockMvc mvc;

    @BeforeEach
    void setup() {
        context = new AnnotationConfigWebApplicationContext();
        context.setServletContext(new MockServletContext());
        context.register(Fixture.class);
        context.refresh();
        service = context.getBean(AiRuntimeRunnerExternalService.class);
        gateway = context.getBean(AiRuntimeGatewayExternalService.class);
        management = context.getBean(AiRuntimeManagementGatewayExternalService.class);
        fallback = context.getBean(AtomicInteger.class);
        mvc = MockMvcBuilders
                .webAppContextSetup(context)
                .addFilters((Filter) context.getBean("springSecurityFilterChain"))
                .build();
        when(service.bootstrap(any(InputStream.class))).thenReturn(ResponseEntity.ok().body("{}".getBytes()));
        when(service.heartbeat(any(InputStream.class))).thenReturn(ResponseEntity.ok().body("{}".getBytes()));
        when(gateway.redeem(any(InputStream.class))).thenReturn(ResponseEntity.ok().body("{}".getBytes()));
        when(gateway.outcome(any(InputStream.class))).thenReturn(ResponseEntity.ok().body("{}".getBytes()));
        when(management.redeem(any(InputStream.class))).thenReturn(ResponseEntity.ok().body("{}".getBytes()));
        when(management.outcome(any(InputStream.class))).thenReturn(ResponseEntity.ok().body("{}".getBytes()));
    }

    @AfterEach
    void close() {
        RuntimeProxyTransport.clear();
        context.close();
    }

    @ParameterizedTest
    @ValueSource(strings = {BOOTSTRAP, HEARTBEAT})
    void absentNativePeerCannotFallBackToBearerCookieOrClaimHeaders(String path) throws Exception {
        var result = mvc
                .perform(post(path)
                        .header("Authorization", "Bearer synthetic-forged")
                        .header("Cookie", "JSESSIONID=synthetic-forged")
                        .header("X-Authenticated-Pod-Uid", UUID.randomUUID())
                        .content("{}"))
                .andReturn()
                .getResponse();
        assertThat(result.getStatus()).isEqualTo(401);
        assertThat(codec.readRuntimeError(result.getContentAsByteArray()).code())
                .isEqualTo(RuntimeErrorCode.UNAUTHENTICATED);
        assertThat(fallback.get()).isZero();
        verifyNoInteractions(service);
    }

    @ParameterizedTest
    @ValueSource(strings = {BOOTSTRAP, HEARTBEAT})
    void exactNativePostReachesOnlyTheCorrespondingExternalService(String path) throws Exception {
        nativePeer();
        var response = mvc
                .perform(post(path).contentType("application/json").content("{}".getBytes()))
                .andReturn()
                .getResponse();
        assertThat(response.getStatus()).isEqualTo(200);
        if (path.equals(BOOTSTRAP)) {
            verify(service).bootstrap(any(InputStream.class));
        } else {
            verify(service).heartbeat(any(InputStream.class));
        }
        verifyNoMoreInteractions(service);
        assertThat(fallback.get()).isZero();
    }

    @ParameterizedTest
    @ValueSource(strings = {
            "/internal/ai-management/probe",
            "/internal/ai-management/",
            "/internal/ai-runtime/v1/controller/workloads/register",
            "/internal/ai-runtime/v1/runner/context/read",
            "/internal/ai-runtime/v1/runner/bootstrap/",
            "/internal/ai-runtime/v1/runner/claims/heartbeat/extra"})
    void nativePeerCannotReachManagementControllerOrUnknownRoutes(String path) throws Exception {
        nativePeer();
        var response = mvc.perform(post(path).content("{}")).andReturn().getResponse();
        assertThat(response.getStatus()).isEqualTo(403);
        assertThat(codec.readRuntimeError(response.getContentAsByteArray()).code()).isEqualTo(RuntimeErrorCode.DENIED);
        assertThat(response.getHeader("Cache-Control")).contains("no-store");
        assertThat(response.getContentAsByteArray()).hasSizeLessThanOrEqualTo(4096);
        assertThat(fallback.get()).isZero();
        verifyNoInteractions(service);
    }

    @Test
    void wrongMethodIsClosedEvenWithNativePeer() throws Exception {
        nativePeer();
        var response = mvc.perform(get(BOOTSTRAP)).andReturn().getResponse();
        assertThat(response.getStatus()).isEqualTo(403);
        assertThat(codec.readRuntimeError(response.getContentAsByteArray()).code()).isEqualTo(RuntimeErrorCode.DENIED);
        verifyNoInteractions(service);
    }

    @Test
    void redispatchCannotReuseNativePeer() throws Exception {
        nativePeer();
        var response = mvc.perform(post(BOOTSTRAP).with(request -> {
            request.setDispatcherType(DispatcherType.FORWARD);
            return request;
        }).content("{}")).andReturn().getResponse();
        assertThat(response.getStatus()).isEqualTo(403);
        verifyNoInteractions(service);
    }

    @Test
    void ordinaryRoutesStillUseTheSeparateNormalChain() throws Exception {
        assertThat(mvc.perform(get("/ordinary")).andReturn().getResponse().getStatus()).isEqualTo(418);
        assertThat(fallback.get()).isEqualTo(1);
        verifyNoInteractions(service);
    }

    @ParameterizedTest
    @ValueSource(
            strings = {"application/json", "application/json; charset=UTF-8", "Application/JSON; charset=\"UTF-8\""})
    void explicitUtf8JsonMetadataReachesController(String type) throws Exception {
        nativePeer();
        assertThat(mvc.perform(post(BOOTSTRAP).contentType(type).content("{}")).andReturn().getResponse().getStatus())
                .isEqualTo(200);
        verify(service).bootstrap(any(InputStream.class));
    }

    @ParameterizedTest
    @ValueSource(strings = {
            "<missing>",
            "text/plain",
            "application/json; charset=ISO-8859-1",
            "application/problem+json",
            "application/json;foo=bar",
            "application/json; charset=UTF-8; charset=UTF-8"})
    void nonJsonOrAmbiguousMetadataIsClosedBeforeController(String type) throws Exception {
        nativePeer();
        var request = post(BOOTSTRAP).content("synthetic-private-metadata-body");
        if (!type.equals("<missing>")) {
            request.contentType(type);
        }
        var response = mvc.perform(request).andReturn().getResponse();
        assertThat(response.getStatus()).isEqualTo(400);
        assertThat(codec.readRuntimeError(response.getContentAsByteArray()).code())
                .isEqualTo(RuntimeErrorCode.INVALID_REQUEST);
        assertThat(response.getContentAsString()).doesNotContain("synthetic-private-metadata-body", type);
        verifyNoInteractions(service);
        assertThat(fallback.get()).isZero();
    }

    @ParameterizedTest
    @ValueSource(strings = {"gzip", "identity", ""})
    void anyContentEncodingIsRejectedBeforeController(String encoding) throws Exception {
        nativePeer();
        var response = mvc
                .perform(post(BOOTSTRAP)
                        .contentType("application/json")
                        .header("Content-Encoding", encoding)
                        .content("{}"))
                .andReturn()
                .getResponse();
        assertThat(response.getStatus()).isEqualTo(400);
        assertThat(codec.readRuntimeError(response.getContentAsByteArray()).code())
                .isEqualTo(RuntimeErrorCode.INVALID_REQUEST);
        verifyNoInteractions(service);
    }

    @Test
    void declaredOversizeIsRejectedBeforeAnyStreamAccess() throws Exception {
        nativePeer();
        var response = mvc.perform(servletContext -> {
            var request = new org.springframework.mock.web.MockHttpServletRequest(servletContext, "POST", BOOTSTRAP) {
                @Override
                public long getContentLengthLong() {
                    return 4097;
                }

                @Override
                public jakarta.servlet.ServletInputStream getInputStream() {
                    throw new AssertionError("oversize body stream accessed");
                }
            };
            request.setContentType("application/json");
            request.setServletPath(BOOTSTRAP);
            return request;
        }).andReturn().getResponse();
        assertThat(response.getStatus()).isEqualTo(413);
        assertThat(codec.readRuntimeError(response.getContentAsByteArray()).code())
                .isEqualTo(RuntimeErrorCode.LIMIT_EXCEEDED);
        verifyNoInteractions(service);
    }

    @Test
    void unknownChunkedLengthReachesOnlyTheExternalService() throws Exception {
        nativePeer();
        var response = mvc.perform(servletContext -> {
            var request = new org.springframework.mock.web.MockHttpServletRequest(servletContext, "POST", BOOTSTRAP) {
                @Override
                public long getContentLengthLong() {
                    return -1;
                }
            };
            request.setContentType("application/json");
            request.setServletPath(BOOTSTRAP);
            request.addHeader("Transfer-Encoding", "chunked");
            request.setContent("{}".getBytes(java.nio.charset.StandardCharsets.UTF_8));
            return request;
        }).andReturn().getResponse();
        assertThat(response.getStatus()).isEqualTo(200);
        verify(service).bootstrap(any(InputStream.class));
    }

    @Test
    void metadataFailureLogHasOnlyFixedCodeAndTheWireCorrelation() throws Exception {
        var logger = (ch.qos.logback.classic.Logger) org.slf4j.LoggerFactory
                .getLogger(AiRuntimeRunnerSecurityConfiguration.class);
        var events = new ch.qos.logback.core.read.ListAppender<ch.qos.logback.classic.spi.ILoggingEvent>();
        var level = logger.getLevel();
        boolean additive = logger.isAdditive();
        logger.setLevel(ch.qos.logback.classic.Level.DEBUG);
        logger.setAdditive(false);
        events.start();
        logger.addAppender(events);
        try {
            nativePeer();
            var response = mvc
                    .perform(post(BOOTSTRAP).contentType("text/plain").content("synthetic-private-metadata-body"))
                    .andReturn()
                    .getResponse();
            assertThat(response.getStatus()).isEqualTo(400);
            var error = codec.readRuntimeError(response.getContentAsByteArray());
            assertThat(events.list).hasSize(1);
            var event = events.list.getFirst();
            assertThat(event.getArgumentArray())
                    .containsExactly("bootstrap", error.code().name(), error.correlationId());
            assertThat(event.getThrowableProxy()).isNull();
            assertThat(event.getFormattedMessage()).doesNotContain("synthetic-private-metadata-body", "text/plain");
        } finally {
            logger.detachAppender(events);
            events.stop();
            logger.setLevel(level);
            logger.setAdditive(additive);
        }
    }

    @ParameterizedTest
    @ValueSource(strings = {"gzip", "multipart"})
    void encodedRawRouteCannotReachBodyOrMultipartConsumers(String form) throws Exception {
        nativePeer();
        var response = mvc.perform(servletContext -> {
            var request = new org.springframework.mock.web.MockHttpServletRequest(servletContext, "POST",
                    "/internal/ai-runtime/v1/runner/%62ootstrap") {
                @Override
                public jakarta.servlet.ServletInputStream getInputStream() {
                    throw new AssertionError("encoded alias reached the body stream");
                }

                @Override
                public java.util.Collection<jakarta.servlet.http.Part> getParts() {
                    throw new AssertionError("encoded alias reached multipart parsing");
                }
            };
            request.setServletPath(BOOTSTRAP); // Native container's decoded servlet path.
            request
                    .setContentType(
                            form.equals("multipart") ? "multipart/form-data; boundary=synthetic" : "application/json");
            if (form.equals("gzip")) {
                request.addHeader("Content-Encoding", "gzip");
            }
            return request;
        }).andReturn().getResponse();
        assertThat(response.getStatus()).isEqualTo(403);
        assertThat(codec.readRuntimeError(response.getContentAsByteArray()).code()).isEqualTo(RuntimeErrorCode.DENIED);
        verifyNoInteractions(service);
    }

    @ParameterizedTest
    @EnumSource(RuntimePeerRole.class)
    void exactRolesCannotCrossRunnerAndRunGatewayChannels(RuntimePeerRole role) throws Exception {
        RuntimeProxyTransport
                .enter(new RuntimePeer(role, new RuntimeProxyCertificateClaims("cluster-one", "ai-proof", "service",
                        "pod-one", UUID.randomUUID())));
        for (String path : new String[]{BOOTSTRAP, HEARTBEAT, REDEEM, OUTCOME, MANAGEMENT_REDEEM, MANAGEMENT_OUTCOME}) {
            boolean permitted = (role == RuntimePeerRole.RUNNER_PROXY
                    && (path.equals(BOOTSTRAP) || path.equals(HEARTBEAT)))
                    || (role == RuntimePeerRole.GATEWAY_RUN && (path.equals(REDEEM) || path.equals(OUTCOME)))
                    || (role == RuntimePeerRole.GATEWAY_MANAGEMENT
                            && (path.equals(MANAGEMENT_REDEEM) || path.equals(MANAGEMENT_OUTCOME)));
            var response = mvc
                    .perform(post(path).contentType("application/json").content("{}"))
                    .andReturn()
                    .getResponse();
            assertThat(response.getStatus()).as("role=%s path=%s", role, path).isEqualTo(permitted ? 200 : 403);
        }
        assertThat(fallback.get()).isZero();
    }

    @ParameterizedTest
    @ValueSource(strings = {REDEEM, OUTCOME})
    void runGatewayMetadataIsBoundedBeforeBodyConsumers(String path) throws Exception {
        gatewayPeer();
        int maximum = path.equals(REDEEM) ? 8192 : 1_500_000;
        var accepted = mvc
                .perform(post(path).contentType("application/json").content(new byte[maximum]))
                .andReturn()
                .getResponse();
        assertThat(accepted.getStatus()).isEqualTo(200);
        var oversized = mvc
                .perform(post(path).contentType("application/json").content(new byte[maximum + 1]))
                .andReturn()
                .getResponse();
        assertThat(oversized.getStatus()).isEqualTo(413);
        assertThat(codec.readRuntimeError(oversized.getContentAsByteArray()).code())
                .isEqualTo(RuntimeErrorCode.LIMIT_EXCEEDED);
        assertThat(
                mvc.perform(post(path).contentType("text/plain").content("{}")).andReturn().getResponse().getStatus())
                .isEqualTo(400);
        assertThat(mvc
                .perform(post(path).contentType("application/json").header("Content-Encoding", "gzip").content("{}"))
                .andReturn()
                .getResponse()
                .getStatus()).isEqualTo(400);
        if (path.equals(REDEEM)) {
            verify(gateway).redeem(any(InputStream.class));
        } else {
            verify(gateway).outcome(any(InputStream.class));
        }
        verifyNoMoreInteractions(gateway);
        verifyNoInteractions(service);
    }

    @ParameterizedTest
    @ValueSource(strings = {REDEEM, OUTCOME})
    void gatewayRoutesHaveNoOrdinaryAuthFallbackOrRedispatch(String path) throws Exception {
        var absent = mvc
                .perform(post(path)
                        .contentType("application/json")
                        .header("Authorization", "Bearer copied")
                        .header("Cookie", "JSESSIONID=copied")
                        .content("{}"))
                .andReturn()
                .getResponse();
        assertThat(absent.getStatus()).isEqualTo(401);
        gatewayPeer();
        assertThat(mvc.perform(get(path)).andReturn().getResponse().getStatus()).isEqualTo(403);
        assertThat(mvc.perform(post(path).contentType("application/json").with(request -> {
            request.setDispatcherType(DispatcherType.FORWARD);
            return request;
        }).content("{}")).andReturn().getResponse().getStatus()).isEqualTo(403);
        assertThat(mvc
                .perform(post(path + "/").contentType("application/json").content("{}"))
                .andReturn()
                .getResponse()
                .getStatus()).isEqualTo(403);
        verifyNoInteractions(service, gateway);
        assertThat(fallback.get()).isZero();
    }

    @ParameterizedTest
    @ValueSource(strings = {MANAGEMENT_REDEEM, MANAGEMENT_OUTCOME})
    void managementMetadataCapsApplyOnlyToItsExactRoleAndNeverUseOrdinaryFallback(String path) throws Exception {
        var absent = mvc
                .perform(post(path)
                        .header("Authorization", "Bearer SYNTHETIC_CANARY")
                        .header("Cookie", "JSESSIONID=SYNTHETIC_CANARY")
                        .content("{}"))
                .andReturn()
                .getResponse();
        assertThat(absent.getStatus()).isEqualTo(401);
        RuntimeProxyTransport
                .enter(new RuntimePeer(RuntimePeerRole.GATEWAY_MANAGEMENT, new RuntimeProxyCertificateClaims(
                        "cluster-one", "ai-proof", "management", "gateway", UUID.randomUUID())));
        int maximum = path.equals(MANAGEMENT_REDEEM) ? 8192 : 1500000;
        assertThat(mvc
                .perform(post(path).contentType("application/json").content(new byte[maximum]))
                .andReturn()
                .getResponse()
                .getStatus()).isEqualTo(200);
        assertThat(mvc
                .perform(post(path).contentType("application/json").content(new byte[maximum + 1]))
                .andReturn()
                .getResponse()
                .getStatus()).isEqualTo(413);
        assertThat(
                mvc.perform(post(path).contentType("text/plain").content("{}")).andReturn().getResponse().getStatus())
                .isEqualTo(400);
        assertThat(mvc
                .perform(post(path).contentType("application/json").header("Content-Encoding", "gzip").content("{}"))
                .andReturn()
                .getResponse()
                .getStatus()).isEqualTo(400);
        assertThat(mvc.perform(get(path)).andReturn().getResponse().getStatus()).isEqualTo(403);
        assertThat(mvc
                .perform(post(path + "/").contentType("application/json").content("{}"))
                .andReturn()
                .getResponse()
                .getStatus()).isEqualTo(403);
        assertThat(fallback.get()).isZero();
        verifyNoInteractions(service, gateway);
    }

    private static void gatewayPeer() {
        RuntimeProxyTransport
                .enter(new RuntimePeer(RuntimePeerRole.GATEWAY_RUN, new RuntimeProxyCertificateClaims("cluster-one",
                        "ai-gateway", "gateway", "gateway-one", UUID.randomUUID())));
    }

    private static void nativePeer() {
        RuntimeProxyTransport
                .enter(new RuntimeProxyCertificateClaims("cluster-one", "ai-proof", "runner", "pod-one",
                        UUID.fromString("30000000-0000-0000-0000-000000000001")));
    }

    @Configuration(proxyBeanMethods = false)
    @EnableWebSecurity
    @EnableWebMvc
    @Import({
            AiRuntimeRunnerSecurityConfiguration.class,
            AiRuntimeRunnerController.class,
            AiRuntimeGatewayController.class,
            AiRuntimeManagementGatewayController.class})
    static class Fixture {
        @Bean
        org.springframework.web.multipart.support.StandardServletMultipartResolver multipartResolver() {
            return new org.springframework.web.multipart.support.StandardServletMultipartResolver();
        }

        @Bean
        AiRuntimeRunnerExternalService service() {
            return mock(AiRuntimeRunnerExternalService.class);
        }

        @Bean
        AiRuntimeGatewayExternalService gateway() {
            return mock(AiRuntimeGatewayExternalService.class);
        }

        @Bean
        AiRuntimeManagementGatewayExternalService management() {
            return mock(AiRuntimeManagementGatewayExternalService.class);
        }

        @Bean
        AtomicInteger fallbackCount() {
            return new AtomicInteger();
        }

        @Bean
        @Order(1)
        SecurityFilterChain ordinaryChain(AtomicInteger count) {
            return new DefaultSecurityFilterChain(AnyRequestMatcher.INSTANCE, (request, response, chain) -> {
                count.incrementAndGet();
                ((jakarta.servlet.http.HttpServletResponse) response).setStatus(418);
            });
        }
    }
}
