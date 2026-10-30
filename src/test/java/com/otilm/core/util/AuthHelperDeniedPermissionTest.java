package com.otilm.core.util;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpSession;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Scope contract of the denied resource/action pair recorded on an authorization failure.
 *
 * <p>
 * The pair is read back by {@code ExceptionHandlingAdvice} to name the permission in a 403 body and by
 * {@code AuditLogAspect} to log it. Both read it during the same request that wrote it, so the pair must not outlive
 * that request: a denial reaching either reader with a previous request's pair still visible would report a decision
 * the caller never triggered.
 */
class AuthHelperDeniedPermissionTest {

    @AfterEach
    void clearRequestContext() {
        RequestContextHolder.resetRequestAttributes();
    }

    private MockHttpServletRequest bindRequest() {
        MockHttpServletRequest request = new MockHttpServletRequest();
        RequestContextHolder.setRequestAttributes(new ServletRequestAttributes(request));
        return request;
    }

    private MockHttpServletRequest bindRequest(MockHttpSession session) {
        MockHttpServletRequest request = bindRequest();
        request.setSession(session);
        return request;
    }

    @Test
    void deniedPairIsReadableWithinTheRequestThatRecordedIt() {
        bindRequest();

        AuthHelper.setDeniedPermissionResourceAction("certificates", "detail");

        assertThat(AuthHelper.getDeniedPermissionResource()).isEqualTo("certificates");
        assertThat(AuthHelper.getDeniedPermissionResourceAction()).isEqualTo("detail");
    }

    /**
     * Session scope would create a session here, which persists a session row for every 403 and lets the pair escape
     * into later requests.
     */
    @Test
    void recordingADeniedPairCreatesNoSession() {
        MockHttpServletRequest request = bindRequest();

        AuthHelper.setDeniedPermissionResourceAction("certificates", "detail");

        assertThat(request.getSession(false)).as("recording a denial must not create a session").isNull();
    }

    /**
     * At session scope, a second request on the same session reads the first request's denial, so a 403 can name a
     * permission that was never checked.
     */
    @Test
    void deniedPairDoesNotLeakIntoALaterRequestOnTheSameSession() {
        MockHttpSession sharedSession = new MockHttpSession();
        bindRequest(sharedSession);
        AuthHelper.setDeniedPermissionResourceAction("certificates", "detail");

        bindRequest(sharedSession);

        assertThat(AuthHelper.getDeniedPermissionResource())
                .as("the pair must not survive into the next request")
                .isNull();
        assertThat(AuthHelper.getDeniedPermissionResourceAction()).isNull();
    }

    @Test
    void readingWithNoBoundRequestYieldsNothing() {
        RequestContextHolder.resetRequestAttributes();

        assertThat(AuthHelper.getDeniedPermissionResource()).isNull();
        assertThat(AuthHelper.getDeniedPermissionResourceAction()).isNull();
    }
}
