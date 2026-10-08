package com.otilm.core.integration.api.web;

import com.otilm.api.model.core.auth.Resource;
import com.otilm.core.model.auth.ResourceAction;
import com.otilm.core.util.BaseSpringBootTest;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.test.web.servlet.MockMvc;

import static org.assertj.core.api.Assertions.assertThat;
import static org.hamcrest.Matchers.startsWith;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * Regression suite for {@code @ExternalAuthorization} over HTTP: the real security filter chain, the method-security
 * advisor behind the controller, and {@code ExceptionHandlingAdvice.handleAccessDeniedException}.
 *
 * <p>
 * The denial cases also guard request-scoped denied-permission recording, since the test schema has no Spring Session
 * tables; {@code /v1/statistics/signingRecords} is the target because it is guarded by both a resource and a parent
 * resource and takes a {@code SecurityFilter} rather than a {@code SecuredUUID}.
 */
@AutoConfigureMockMvc
class ExternalAuthorizationHttpITest extends BaseSpringBootTest {

    private static final String STATISTICS_ENDPOINT = "/v1/statistics/signingRecords";

    @Autowired
    private MockMvc mockMvc;

    /**
     * The body's own {@code statusCode} field is not asserted: it is filled in by the interfaces module, which reported
     * 400 for every error until interfaces#887. Assert it once core consumes a build carrying that fix.
     */
    @Test
    void returnsForbiddenProblemJsonNamingTheDeniedResourceAndAction() throws Exception {
        denyResourceAccess(Resource.SIGNING_RECORD, ResourceAction.LIST);

        mockMvc
                .perform(get(STATISTICS_ENDPOINT))
                .andExpectAll(status().isForbidden(), content().contentType("application/problem+json"),
                        jsonPath("$.code").value("ACCESS_DENIED"),
                        jsonPath("$.message").value("Access Denied. Required 'List' permission for 'Signing Record'"));
    }

    @Test
    void namesTheParentResourceWhenTheParentCheckIsDenied() throws Exception {
        denyResourceAccess(Resource.SIGNING_PROFILE, ResourceAction.LIST);

        mockMvc
                .perform(get(STATISTICS_ENDPOINT))
                .andExpectAll(status().isForbidden(), jsonPath("$.code").value("ACCESS_DENIED"),
                        jsonPath("$.message").value("Access Denied. Required 'List' permission for 'Signing Profile'"));
    }

    @Test
    void returnsForbiddenWhenTheDenialRecordedNoPermissionPair() throws Exception {
        when(opaClient.checkObjectAccess(any(), any(), any(), any()))
                .thenThrow(new AccessDeniedException("An error occurred when calling OPA."));

        mockMvc
                .perform(get(STATISTICS_ENDPOINT))
                .andExpectAll(status().isForbidden(), jsonPath("$.code").value("ACCESS_DENIED"),
                        jsonPath("$.message").value(startsWith("Access denied for the specified operation")));
    }

    @Test
    void sendsNoObjectUuidsForASecurityFilterEndpoint() throws Exception {
        mockMvc.perform(get(STATISTICS_ENDPOINT)).andExpect(status().isOk());

        assertThat(captureOpaRequests())
                .as("the guarded service method was reached through the advisor")
                .isNotEmpty()
                .allSatisfy(request -> assertThat(request.getObjectUUIDs()).isNull());
    }
}
