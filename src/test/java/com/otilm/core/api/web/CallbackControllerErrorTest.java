package com.otilm.core.api.web;

import com.otilm.api.exception.ConnectorProblemException;
import com.otilm.api.model.common.attribute.common.callback.RequestAttributeCallback;
import com.otilm.api.model.common.error.ErrorCode;
import com.otilm.api.model.common.error.ProblemDetailExtended;
import com.otilm.core.api.ExceptionHandlingAdvice;
import com.otilm.core.service.CallbackExternalService;
import java.util.UUID;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;

import static org.hamcrest.Matchers.containsString;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * A connector answering an attribute callback with 401 problem+json must surface from Core's callback endpoint as 502,
 * never as Core's own 401 — clients read a bare 401 as a dead session.
 */
class CallbackControllerErrorTest {

    private static final UUID CONNECTOR_UUID = UUID.fromString("11111111-2222-4333-8444-555555555555");

    private MockMvc mockMvc;

    @BeforeEach
    void setUp() throws Exception {
        ProblemDetailExtended problemDetail = new ProblemDetailExtended();
        problemDetail.setStatus(401);
        problemDetail.setTitle("Credentials invalid for upstream system");
        problemDetail.setDetail("Credentials invalid for upstream system");
        problemDetail.setErrorCode(ErrorCode.CREDENTIAL_INVALID);
        problemDetail.setRetryable(false);

        CallbackExternalService callbackService = mock(CallbackExternalService.class);
        when(callbackService.callback(eq(CONNECTOR_UUID), any(RequestAttributeCallback.class)))
                .thenThrow(new ConnectorProblemException(problemDetail));

        CallbackControllerImpl controller = new CallbackControllerImpl();
        controller.setCallbackService(callbackService);
        mockMvc = MockMvcBuilders
                .standaloneSetup(controller)
                .setControllerAdvice(new ExceptionHandlingAdvice())
                .build();
    }

    @Test
    void connectorAuthFailureOnCallbackSurfacesAsBadGateway() throws Exception {
        mockMvc
                .perform(post("/v2/connectors/{uuid}/callback", CONNECTOR_UUID)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{}"))
                .andExpect(status().isBadGateway())
                .andExpect(jsonPath("$.message", containsString("Original response code 401")));
    }
}
