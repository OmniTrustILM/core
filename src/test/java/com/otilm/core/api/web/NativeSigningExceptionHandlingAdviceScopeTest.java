package com.otilm.core.api.web;

import com.jayway.jsonpath.JsonPath;
import com.otilm.api.exception.ConnectorCommunicationException;
import com.otilm.core.api.ExceptionHandlingAdvice;
import com.otilm.core.signing.engine.error.SigningEngineException;
import com.otilm.core.signing.engine.error.SigningEngineFailure;
import com.otilm.core.util.ApplicationMessageConverters;
import java.net.ConnectException;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;

/**
 * Pins where the native signing advice answers: ahead of the global advice for the native controller, and not at all
 * for any other controller, which keeps the global advice's answers.
 */
class NativeSigningExceptionHandlingAdviceScopeTest {

    private static final String NATIVE_FAILURE_PATH = "/v1/signing/failure";
    private static final String UNRELATED_FAILURE_PATH = "/v1/unrelated/failure";
    private static final String CLIENT = "The document does not satisfy the signing profile.";
    private static final String COMMUNICATION_FAILURE = "Error in connector signer communication";

    private final FailingNativeSigningController nativeController = new FailingNativeSigningController();
    private final FailingUnrelatedController unrelatedController = new FailingUnrelatedController();
    private MockMvc mockMvc;

    @BeforeEach
    void buildMockMvc() {
        // The global advice is registered first, so only the native advice's own precedence can put it ahead.
        mockMvc = MockMvcBuilders
                .standaloneSetup(nativeController, unrelatedController)
                .setMessageConverters(ApplicationMessageConverters.get())
                .setControllerAdvice(new ExceptionHandlingAdvice(), new NativeSigningExceptionHandlingAdvice())
                .build();
    }

    @Test
    void answers502WithErrorMessage_whenNativeEndpointFailsWithSignerFault() throws Exception {
        // given
        var signerFault = new SigningEngineException(SigningEngineFailure.SIGNER_FAULT, "signer refused", CLIENT);
        nativeController.failWith(signerFault);

        // when
        MockHttpServletResponse response = mockMvc.perform(post(NATIVE_FAILURE_PATH)).andReturn().getResponse();

        // then
        assertThat(response.getStatus()).isEqualTo(HttpStatus.BAD_GATEWAY.value());
        assertThat(messageOf(response)).isEqualTo(CLIENT);
        assertThat(response.containsHeader(HttpHeaders.RETRY_AFTER)).isFalse();
    }

    @Test
    void answers503WithRetryAfter_whenNativeEndpointLosesConnector() throws Exception {
        // given
        var connectorOutage = new ConnectorCommunicationException(COMMUNICATION_FAILURE,
                new ConnectException("Connection refused"), null);
        nativeController.failWith(connectorOutage);

        // when
        MockHttpServletResponse response = mockMvc.perform(post(NATIVE_FAILURE_PATH)).andReturn().getResponse();

        // then
        assertThat(response.getStatus()).isEqualTo(HttpStatus.SERVICE_UNAVAILABLE.value());
        assertThat(response.getHeader(HttpHeaders.RETRY_AFTER)).isEqualTo("30");
        assertThat(messageOf(response)).isEqualTo("The connector is unavailable.");
    }

    @Test
    void answersWithGlobalAdvice_whenUnrelatedEndpointFailsWithSignerFault() throws Exception {
        // given
        var signerFault = new SigningEngineException(SigningEngineFailure.SIGNER_FAULT, "signer refused", CLIENT);
        unrelatedController.failWith(signerFault);

        // when
        MockHttpServletResponse response = mockMvc.perform(post(UNRELATED_FAILURE_PATH)).andReturn().getResponse();

        // then
        assertThat(response.getStatus()).isEqualTo(HttpStatus.INTERNAL_SERVER_ERROR.value());
        assertThat(messageOf(response)).isEqualTo("Internal server error.");
    }

    @Test
    void answersWithGlobalAdvice_whenUnrelatedEndpointLosesConnector() throws Exception {
        // given
        var connectorOutage = new ConnectorCommunicationException(COMMUNICATION_FAILURE,
                new ConnectException("Connection refused"), null);
        unrelatedController.failWith(connectorOutage);

        // when
        MockHttpServletResponse response = mockMvc.perform(post(UNRELATED_FAILURE_PATH)).andReturn().getResponse();

        // then
        assertThat(response.getStatus()).isEqualTo(HttpStatus.SERVICE_UNAVAILABLE.value());
        assertThat(response.containsHeader(HttpHeaders.RETRY_AFTER)).isFalse();
        assertThat(messageOf(response)).isEqualTo(COMMUNICATION_FAILURE);
    }

    // ── Helpers ───────────────────────────────────────────────────────────────

    private static String messageOf(MockHttpServletResponse response) throws Exception {
        return JsonPath.read(response.getContentAsString(), "$.message");
    }

    /** A native endpoint, which the native advice covers because it is assignable to the native controller. */
    @RestController
    static class FailingNativeSigningController extends NativeSigningControllerImpl {

        private Exception failure;

        void failWith(Exception failure) {
            this.failure = failure;
        }

        @PostMapping("/failure")
        public void fail() throws Exception {
            throw failure;
        }
    }

    @RestController
    @RequestMapping("/v1/unrelated")
    static class FailingUnrelatedController {

        private Exception failure;

        void failWith(Exception failure) {
            this.failure = failure;
        }

        @PostMapping("/failure")
        public void fail() throws Exception {
            throw failure;
        }
    }
}
