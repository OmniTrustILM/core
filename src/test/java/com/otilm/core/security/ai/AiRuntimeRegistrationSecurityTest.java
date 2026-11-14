package com.otilm.core.security.ai;

import com.otilm.core.api.ai.AiRuntimeControllerController;
import com.otilm.core.api.ai.AiRuntimeControllerRegistrationController;
import com.otilm.core.service.AiRuntimeControllerExternalService;
import com.otilm.core.service.AiRuntimeControllerRegistrationExternalService;
import com.otilm.core.service.AiRuntimeGatewayExternalService;
import com.otilm.core.service.AiRuntimeManagementGatewayExternalService;
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
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Import;
import org.springframework.http.ResponseEntity;
import org.springframework.mock.web.MockServletContext;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.web.context.support.AnnotationConfigWebApplicationContext;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;

class AiRuntimeRegistrationSecurityTest {
    private static final String RUN = "/internal/ai-runtime/v1/gateway/run/registration";
    private static final String MANAGEMENT = "/internal/ai-management/v1/gateway/registration";
    private AnnotationConfigWebApplicationContext context;
    private MockMvc mvc;
    private AiRuntimeGatewayExternalService run;
    private AiRuntimeManagementGatewayExternalService management;
    private AiRuntimeControllerExternalService controller;
    private AiRuntimeControllerRegistrationExternalService publication;

    @BeforeEach
    void setup() {
        context = new AnnotationConfigWebApplicationContext();
        context.setServletContext(new MockServletContext());
        context.register(Fixture.class);
        context.refresh();
        mvc = MockMvcBuilders
                .webAppContextSetup(context)
                .addFilters((Filter) context.getBean("springSecurityFilterChain"))
                .build();
        run = context.getBean(AiRuntimeGatewayExternalService.class);
        management = context.getBean(AiRuntimeManagementGatewayExternalService.class);
        controller = context.getBean(AiRuntimeControllerExternalService.class);
        publication = context.getBean(AiRuntimeControllerRegistrationExternalService.class);
        var ok = ResponseEntity.ok().body("{}".getBytes(java.nio.charset.StandardCharsets.UTF_8));
        when(run.registration()).thenReturn(ok);
        when(management.registration()).thenReturn(ok);
        when(controller.reconcile(any(InputStream.class))).thenReturn(ok);
        when(controller.register(any(InputStream.class))).thenReturn(ok);
        when(controller.status(any(InputStream.class))).thenReturn(ok);
        when(controller.cleanup(any(InputStream.class))).thenReturn(ok);
        when(publication.observeRunGateway()).thenReturn(ok);
        when(publication.observeManagementGateway()).thenReturn(ok);
    }

    @AfterEach
    void close() {
        RuntimeProxyTransport.clear();
        context.close();
    }

    @ParameterizedTest
    @EnumSource(RuntimePeerRole.class)
    void onlyOwnNativeRoleCanReachEachGetStatus(RuntimePeerRole role) throws Exception {
        peer(role);
        assertThat(mvc.perform(get(RUN)).andReturn().getResponse().getStatus())
                .isEqualTo(role == RuntimePeerRole.GATEWAY_RUN ? 200 : 403);
        assertThat(mvc.perform(get(MANAGEMENT)).andReturn().getResponse().getStatus())
                .isEqualTo(role == RuntimePeerRole.GATEWAY_MANAGEMENT ? 200 : 403);
        assertThat(context.getBean(AtomicInteger.class)).hasValue(0);
        verifyNoInteractions(controller);
    }

    @Test
    void statusCannotAcceptBodiesQueriesCredentialsOrRedispatch() throws Exception {
        peer(RuntimePeerRole.GATEWAY_RUN);
        assertThat(mvc.perform(get(RUN).content("{}")).andReturn().getResponse().getStatus()).isEqualTo(400);
        assertThat(mvc.perform(get(RUN).queryParam("role", "GATEWAY_MANAGEMENT")).andReturn().getResponse().getStatus())
                .isEqualTo(400);
        assertThat(mvc.perform(get(RUN).contentType("application/json")).andReturn().getResponse().getStatus())
                .isEqualTo(400);
        for (String header : new String[]{
                "Authorization",
                "Cookie",
                "Cookie2",
                "Content-Encoding",
                "Transfer-Encoding"}) {
            assertThat(mvc.perform(get(RUN).header(header, "synthetic-selector")).andReturn().getResponse().getStatus())
                    .isEqualTo(400);
        }
        assertThat(mvc.perform(get(RUN).with(request -> {
            request.setDispatcherType(DispatcherType.FORWARD);
            return request;
        })).andReturn().getResponse().getStatus()).isEqualTo(403);
        assertThat(mvc
                .perform(post(RUN).contentType("application/json").content("{}"))
                .andReturn()
                .getResponse()
                .getStatus()).isEqualTo(403);
        verifyNoInteractions(run, management, controller);
    }

    @Test
    void noNativePeerCanBorrowOrdinaryBearerOrCookieForStatus() throws Exception {
        for (String path : new String[]{RUN, MANAGEMENT}) {
            assertThat(mvc
                    .perform(get(path)
                            .header("Authorization", "Bearer synthetic-forged")
                            .header("Cookie", "JSESSIONID=synthetic-forged"))
                    .andReturn()
                    .getResponse()
                    .getStatus()).isEqualTo(401);
        }
        verifyNoInteractions(run, management, controller);
        assertThat(context.getBean(AtomicInteger.class)).hasValue(0);
    }

    @ParameterizedTest
    @EnumSource(RuntimePeerRole.class)
    void controllerPostsRequireTheirActualControllerRole(RuntimePeerRole role) throws Exception {
        peer(role);
        for (String suffix : new String[]{
                "launches/reconcile",
                "workloads/register",
                "workloads/status",
                "cleanup/reconcile"}) {
            var response = mvc
                    .perform(post("/internal/ai-runtime/v1/controller/" + suffix)
                            .contentType("application/json")
                            .content("{}"))
                    .andReturn()
                    .getResponse();
            assertThat(response.getStatus()).isEqualTo(role == RuntimePeerRole.CONTROLLER ? 200 : 403);
        }
        verifyNoInteractions(run, management);
        assertThat(context.getBean(AtomicInteger.class)).hasValue(0);
    }

    @ParameterizedTest
    @EnumSource(RuntimePeerRole.class)
    void fixedBodylessGatewayObservationPostsRequireTheControllerChannel(RuntimePeerRole role) throws Exception {
        peer(role);
        for (String path : new String[]{
                "/internal/ai-runtime/v1/controller/gateways/run/observe",
                "/internal/ai-management/v1/controller/gateway/observe"}) {
            assertThat(mvc.perform(post(path)).andReturn().getResponse().getStatus())
                    .isEqualTo(role == RuntimePeerRole.CONTROLLER ? 200 : 403);
        }
        verifyNoInteractions(run, management, controller);
        assertThat(context.getBean(AtomicInteger.class)).hasValue(0);
    }

    @Test
    void publicationHasNoCallerRoleRunClaimOrBodySelector() throws Exception {
        peer(RuntimePeerRole.CONTROLLER);
        for (String path : new String[]{
                "/internal/ai-runtime/v1/controller/gateways/run/observe",
                "/internal/ai-management/v1/controller/gateway/observe"}) {
            assertThat(mvc
                    .perform(post(path).contentType("application/json").content("{\"runId\":\"synthetic\"}"))
                    .andReturn()
                    .getResponse()
                    .getStatus()).isEqualTo(400);
            assertThat(mvc.perform(post(path).queryParam("role", "GATEWAY_RUN")).andReturn().getResponse().getStatus())
                    .isEqualTo(400);
            assertThat(mvc
                    .perform(post(path).header("Authorization", "Bearer synthetic-forged"))
                    .andReturn()
                    .getResponse()
                    .getStatus()).isEqualTo(400);
        }
        verifyNoInteractions(run, management, controller, publication);
    }

    private static void peer(RuntimePeerRole role) {
        RuntimeProxyTransport
                .enter(new RuntimePeer(role,
                        new RuntimeProxyCertificateClaims("lab", "runtime", "service", "pod", UUID.randomUUID())));
    }

    @Configuration(proxyBeanMethods = false)
    @Import({
            AiRuntimeRunnerSecurityTest.Fixture.class,
            AiRuntimeControllerController.class,
            AiRuntimeControllerRegistrationController.class})
    static class Fixture {
        @Bean
        AiRuntimeControllerRegistrationExternalService publication() {
            return mock(AiRuntimeControllerRegistrationExternalService.class);
        }

        @Bean
        AiRuntimeControllerExternalService controller() {
            return mock(AiRuntimeControllerExternalService.class);
        }
    }
}
