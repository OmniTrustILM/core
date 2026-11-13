package com.otilm.core.api.est;

import com.otilm.api.model.core.auth.Resource;
import com.otilm.api.model.core.logging.enums.Module;
import com.otilm.api.model.core.logging.enums.Operation;
import com.otilm.core.aop.AuditLogged;
import com.otilm.core.aop.AuditOperationOverride;
import com.otilm.core.service.est.EstExternalService;
import com.otilm.core.service.est.authentication.EstClientCredentials;
import java.lang.reflect.Method;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.stream.Stream;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.http.HttpHeaders;
import org.springframework.http.ResponseEntity;
import org.springframework.mock.web.MockHttpServletRequest;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Named.named;
import static org.junit.jupiter.params.provider.Arguments.arguments;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoMoreInteractions;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class EstControllerImplTest {

    private static final String CERTIFICATE_HEADER = "ssl-client-cert";
    private static final String LABEL = "devices";
    private static final byte[] REQUEST_BODY = "MIIB".getBytes(StandardCharsets.US_ASCII);

    @Mock
    private EstExternalService estService;

    @Mock
    private AuditOperationOverride auditOperationOverride;

    private MockHttpServletRequest httpRequest;
    private EstControllerImpl controller;

    @BeforeEach
    void createController() {
        httpRequest = new MockHttpServletRequest();
        controller = new EstControllerImpl(estService, auditOperationOverride, httpRequest, CERTIFICATE_HEADER);
    }

    // ── Delegation ────────────────────────────────────────────────────────────

    @Nested
    class Delegation {

        @Test
        void returnsTheServiceResponse_whenCaCertificatesAreRequested() {
            // given
            ResponseEntity<byte[]> served = ResponseEntity.ok(REQUEST_BODY);
            when(estService.getCaCertificates(LABEL)).thenReturn(served);

            // when
            ResponseEntity<byte[]> response = controller.getCaCertificates(LABEL);

            // then
            assertThat(response).isSameAs(served);
        }

        @Test
        void passesNoLabelOn_whenRequestIsUnlabelled() {
            // given
            String noLabel = null;

            // when
            controller.getCaCertificates(noLabel);

            // then
            verify(estService).getCaCertificates(null);
            verifyNoMoreInteractions(estService);
        }

        @Test
        void returnsTheServiceResponse_whenCsrAttributesAreRequested() {
            // given
            ResponseEntity<byte[]> served = ResponseEntity.noContent().build();
            when(estService.getCsrAttributes(LABEL)).thenReturn(served);

            // when
            ResponseEntity<byte[]> response = controller.getCsrAttributes(LABEL);

            // then
            assertThat(response).isSameAs(served);
        }

        @Test
        void handsTheBasicCredentialsOfTheRequestOn_whenEnrolling() {
            // given
            var username = "device-owner";
            var password = "p4ssw0rd";
            httpRequest.addHeader(HttpHeaders.AUTHORIZATION, basic(username + ":" + password));
            ResponseEntity<byte[]> served = ResponseEntity.ok(REQUEST_BODY);
            when(estService.simpleEnroll(eq(LABEL), eq(REQUEST_BODY), any(EstClientCredentials.class)))
                    .thenReturn(served);

            // when
            ResponseEntity<byte[]> response = controller.simpleEnroll(LABEL, REQUEST_BODY);

            // then
            ArgumentCaptor<EstClientCredentials> credentials = ArgumentCaptor.forClass(EstClientCredentials.class);
            verify(estService).simpleEnroll(eq(LABEL), eq(REQUEST_BODY), credentials.capture());
            assertThat(response).isSameAs(served);
            assertThat(credentials.getValue().basic()).hasValueSatisfying(basic -> {
                assertThat(basic.username()).isEqualTo(username);
                assertThat(basic.password()).isEqualTo(password);
            });
        }

        @Test
        void readsTheCertificateHeaderNamedByTheConfiguration_whenEnrolling() {
            // given
            httpRequest.addHeader(CERTIFICATE_HEADER, "not a certificate");

            // when
            controller.simpleEnroll(LABEL, REQUEST_BODY);

            // then
            ArgumentCaptor<EstClientCredentials> credentials = ArgumentCaptor.forClass(EstClientCredentials.class);
            verify(estService).simpleEnroll(eq(LABEL), eq(REQUEST_BODY), credentials.capture());
            assertThat(credentials.getValue().certificateMalformed()).isTrue();
        }

        @Test
        void handsTheCredentialsOn_whenReenrolling() {
            // given
            ResponseEntity<byte[]> served = ResponseEntity.ok(REQUEST_BODY);
            when(estService.simpleReenroll(eq(LABEL), eq(REQUEST_BODY), any(EstClientCredentials.class)))
                    .thenReturn(served);

            // when
            ResponseEntity<byte[]> response = controller.simpleReenroll(LABEL, REQUEST_BODY);

            // then
            assertThat(response).isSameAs(served);
        }

        @Test
        void handsTheCredentialsOn_whenGeneratingTheKeyOnTheServer() {
            // given
            ResponseEntity<byte[]> served = ResponseEntity.ok(REQUEST_BODY);
            when(estService.serverKeyGeneration(eq(LABEL), eq(REQUEST_BODY), any(EstClientCredentials.class)))
                    .thenReturn(served);

            // when
            ResponseEntity<byte[]> response = controller.serverKeyGeneration(LABEL, REQUEST_BODY);

            // then
            assertThat(response).isSameAs(served);
        }
    }

    // ── Audit ─────────────────────────────────────────────────────────────────

    /**
     * The audit aspect reads the operation from the annotation, or from the override for an endpoint annotated with
     * {@link Operation#UNKNOWN}.
     */
    @Nested
    class Audit {

        @Test
        void namesARenewal_whenReenrolling() {
            // given — a re-enrolment, which the service names a rekey once it sees a new key

            // when
            controller.simpleReenroll(LABEL, REQUEST_BODY);

            // then
            verify(auditOperationOverride).set(Operation.RENEW);
        }

        @ParameterizedTest
        @MethodSource("auditedOperations")
        void declaresTheOperationOfTheEndpoint(Method endpoint, Operation operation) {
            // given — an endpoint of the controller

            // when
            AuditLogged audited = endpoint.getAnnotation(AuditLogged.class);

            // then
            assertThat(audited).isNotNull();
            assertThat(audited.module()).isEqualTo(Module.PROTOCOLS);
            assertThat(audited.resource()).isEqualTo(Resource.CERTIFICATE);
            assertThat(audited.affiliatedResource()).isEqualTo(Resource.EST_PROFILE);
            assertThat(audited.operation()).isEqualTo(operation);
        }

        @Test
        void writesTheRecordBeforeAnswering_whenTheEndpointHandsOutAKey() throws Exception {
            // given
            Method serverKeyGeneration = endpoint("serverKeyGeneration", String.class, byte[].class);

            // when
            AuditLogged audited = serverKeyGeneration.getAnnotation(AuditLogged.class);

            // then
            assertThat(audited.synchronous()).isTrue();
        }

        static Stream<Arguments> auditedOperations() throws NoSuchMethodException {
            return Stream
                    .of(arguments(named("cacerts", endpoint("getCaCertificates", String.class)), Operation.GET_CHAIN),
                            arguments(named("csrattrs", endpoint("getCsrAttributes", String.class)),
                                    Operation.EST_CSR_ATTRIBUTES),
                            arguments(named("simpleenroll", endpoint("simpleEnroll", String.class, byte[].class)),
                                    Operation.ISSUE),
                            arguments(named("simplereenroll", endpoint("simpleReenroll", String.class, byte[].class)),
                                    Operation.UNKNOWN),
                            arguments(
                                    named("serverkeygen", endpoint("serverKeyGeneration", String.class, byte[].class)),
                                    Operation.EST_SERVER_KEY_GENERATION));
        }
    }

    // ── Helpers ───────────────────────────────────────────────────────────────

    private static Method endpoint(String name, Class<?>... parameterTypes) throws NoSuchMethodException {
        return EstControllerImpl.class.getMethod(name, parameterTypes);
    }

    private static String basic(String userAndPassword) {
        byte[] credentials = userAndPassword.getBytes(StandardCharsets.UTF_8);
        return "Basic " + Base64.getEncoder().encodeToString(credentials);
    }
}
