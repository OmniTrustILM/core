package com.otilm.core.config;

import ch.qos.logback.classic.Level;
import ch.qos.logback.classic.Logger;
import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.core.read.ListAppender;
import com.otilm.api.exception.ValidationException;
import com.otilm.api.model.core.est.EstMediaTypes;
import com.otilm.core.service.est.message.EstBoundedRequest;
import com.otilm.core.service.est.message.EstError;
import com.otilm.core.service.est.message.EstException;
import com.otilm.core.service.est.message.EstRequestGuard;
import com.otilm.core.util.AuthHelper;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletRequest;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.List;
import org.assertj.core.api.ThrowableAssert.ThrowingCallable;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.mockito.ArgumentCaptor;
import org.mockito.InOrder;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.test.util.ReflectionTestUtils;
import org.springframework.web.servlet.HandlerExceptionResolver;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.assertj.core.api.InstanceOfAssertFactories.STRING;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.same;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.inOrder;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.verifyNoMoreInteractions;

/**
 * Unit tests for {@link ProtocolValidationFilter} — the global protocol gate is deny-by-default over
 * {@code /{context}/v*\/protocols/**}. TSP requests are authenticated by the dedicated TSP security chain, so this
 * filter must pass {@code tsp/} through untouched (no system-user authentication, no 422). EST requests, which live
 * under {@code .well-known/est/}, are checked by the {@link EstRequestGuard} first: a refusal is written as plain text
 * with no authentication and no further filtering, and an admitted request is authenticated as the {@code est} system
 * user and continues with a body that cannot exceed the limit.
 */
@ExtendWith(MockitoExtension.class)
class ProtocolValidationFilterTest {

    private static final String CONTEXT = "/api";
    private static final String EST_BASE = CONTEXT + "/v1/protocols/.well-known/est/";
    private static final String ENROLLMENT_PATH = EST_BASE + "devices/simpleenroll";
    private static final MediaType PLAIN_TEXT_UTF8 = MediaType.parseMediaType("text/plain; charset=UTF-8");

    private final ListAppender<ILoggingEvent> logged = new ListAppender<>();
    private final Logger filterLogger = (Logger) LoggerFactory.getLogger(ProtocolValidationFilter.class);

    private ProtocolValidationFilter filter;

    @Mock
    private FilterChain filterChain;

    @Mock
    private HandlerExceptionResolver resolver;

    @Mock
    private AuthHelper authHelper;

    @BeforeEach
    void createFilterAndCaptureItsLog() {
        filter = new ProtocolValidationFilter();
        filter.setAuthHelper(authHelper);
        filter.setHandlerExceptionResolver(resolver);
        ReflectionTestUtils.setField(filter, "context", CONTEXT);
        logged.start();
        filterLogger.addAppender(logged);
    }

    @AfterEach
    void releaseTheFilterLog() {
        filterLogger.detachAppender(logged);
    }

    @Test
    void passesThrough_whenTspRequest_withoutSystemUserAuthOrRejection() throws Exception {
        // given
        MockHttpServletRequest request = new MockHttpServletRequest("POST",
                CONTEXT + "/v1/protocols/tsp/some-profile/sign");
        request.setContent(new byte[0]);

        // when
        filter.doFilter(request, new MockHttpServletResponse(), filterChain);

        // then
        verify(filterChain, times(1)).doFilter(any(), any());
        verify(resolver, never()).resolveException(any(), any(), any(), any());
        // The dedicated TSP chain owns authentication; this filter must not overwrite the principal.
        verifyNoInteractions(authHelper);
    }

    @Test
    void rejects_whenUnknownProtocol_withValidationException() throws Exception {
        // given
        MockHttpServletRequest request = new MockHttpServletRequest("POST", CONTEXT + "/v1/protocols/unknown/foo");
        request.setContent(new byte[0]);

        // when
        filter.doFilter(request, new MockHttpServletResponse(), filterChain);

        // then
        verify(resolver, times(1)).resolveException(any(), any(), any(), any(ValidationException.class));
        verify(filterChain, never()).doFilter(any(), any());
    }

    @Test
    void authenticatesAsTheEstUser_whenEstRequest() throws Exception {
        // given
        var labelledEstPath = CONTEXT + "/v1/protocols/.well-known/est/devices/simpleenroll";
        MockHttpServletRequest request = new MockHttpServletRequest("POST", labelledEstPath);
        request.setContentType(EstMediaTypes.PKCS10);
        request.setContent(new byte[0]);

        // when
        filter.doFilter(request, new MockHttpServletResponse(), filterChain);

        // then
        verifyAuthenticatedAsEstUserBeforeTheChain();
    }

    @Test
    void authenticatesAsTheEstUser_whenUnlabelledEstRequest() throws Exception {
        // given
        var unlabelledEstPath = CONTEXT + "/v1/protocols/.well-known/est/cacerts";
        MockHttpServletRequest request = new MockHttpServletRequest("GET", unlabelledEstPath);

        // when
        filter.doFilter(request, new MockHttpServletResponse(), filterChain);

        // then
        verifyAuthenticatedAsEstUserBeforeTheChain();
    }

    @Test
    void writesNotFound_whenEstOperationIsUnknown() throws Exception {
        // given
        var unknownOperation = EST_BASE + "fullcmc";
        MockHttpServletRequest request = new MockHttpServletRequest("GET", unknownOperation);
        MockHttpServletResponse response = new MockHttpServletResponse();

        // when
        filter.doFilter(request, response, filterChain);

        // then
        assertRefusedAs(EstError.NOT_FOUND, response);
        verifyNothingDispatched();
    }

    @Test
    void writesMethodNotAllowed_withAllowHeader_whenGetTargetsSimpleEnroll() throws Exception {
        // given
        var methodTheEnrollmentDoesNotAccept = "GET";
        MockHttpServletRequest request = new MockHttpServletRequest(methodTheEnrollmentDoesNotAccept, ENROLLMENT_PATH);
        MockHttpServletResponse response = new MockHttpServletResponse();

        // when
        filter.doFilter(request, response, filterChain);

        // then
        assertRefusedAs(EstError.METHOD_NOT_ALLOWED, response);
        assertThat(response.getHeader(HttpHeaders.ALLOW)).isEqualTo("POST");
        verifyNothingDispatched();
    }

    @Test
    void writesUnsupportedMediaType_whenEnrollmentIsNotPkcs10() throws Exception {
        // given
        var notPkcs10 = MediaType.APPLICATION_JSON_VALUE;
        MockHttpServletRequest request = new MockHttpServletRequest("POST", ENROLLMENT_PATH);
        request.setContentType(notPkcs10);
        request.setContent(new byte[0]);
        MockHttpServletResponse response = new MockHttpServletResponse();

        // when
        filter.doFilter(request, response, filterChain);

        // then
        assertRefusedAs(EstError.UNSUPPORTED_MEDIA_TYPE, response);
        verifyNothingDispatched();
    }

    @Test
    void writesPayloadTooLarge_whenContentLengthExceedsTheLimit() throws Exception {
        // given
        byte[] bodyOverTheLimit = new byte[EstRequestGuard.MAX_BODY_BYTES + 1];
        MockHttpServletRequest request = anEnrollmentRequest(bodyOverTheLimit);
        MockHttpServletResponse response = new MockHttpServletResponse();

        // when
        filter.doFilter(request, response, filterChain);

        // then
        assertRefusedAs(EstError.PAYLOAD_TOO_LARGE, response);
        verifyNothingDispatched();
    }

    @Test
    void throwsPayloadTooLarge_whenChunkedBodyExceedsTheLimitWhileRead() throws Exception {
        // given — a chunked body declares no length, so only reading it can show that it is too large
        byte[] bodyOverTheLimit = new byte[EstRequestGuard.MAX_BODY_BYTES + 1];
        MockHttpServletRequest request = aChunkedEnrollmentRequest(bodyOverTheLimit);
        doAnswer(invocation -> {
            ServletRequest chainRequest = invocation.getArgument(0);
            chainRequest.getInputStream().readAllBytes();
            return null;
        }).when(filterChain).doFilter(any(), any());

        // when
        ThrowingCallable filterWhileTheChainReadsTheBody = () -> filter
                .doFilter(request, new MockHttpServletResponse(), filterChain);

        // then
        assertThatThrownBy(filterWhileTheChainReadsTheBody)
                .isInstanceOfSatisfying(EstException.class,
                        thrown -> assertThat(thrown.error()).isEqualTo(EstError.PAYLOAD_TOO_LARGE));
    }

    @Test
    void continuesAsEst_withBoundedBody_whenRequestIsAdmitted() throws Exception {
        // given — a body as large as the limit allows
        byte[] bodyAtTheLimit = new byte[EstRequestGuard.MAX_BODY_BYTES];
        Arrays.fill(bodyAtTheLimit, (byte) 'A');
        MockHttpServletRequest request = anEnrollmentRequest(bodyAtTheLimit);
        MockHttpServletResponse response = new MockHttpServletResponse();

        // when
        filter.doFilter(request, response, filterChain);

        // then
        verifyAuthenticatedAsEstUserBeforeTheChain();
        ArgumentCaptor<ServletRequest> forwarded = ArgumentCaptor.forClass(ServletRequest.class);
        verify(filterChain).doFilter(forwarded.capture(), same(response));
        assertThat(forwarded.getValue()).isInstanceOf(EstBoundedRequest.class);
        assertThat(forwarded.getValue().getInputStream().readAllBytes()).isEqualTo(bodyAtTheLimit);
    }

    @Test
    void logsOnlyTheReasonAndMethod_whenARequestIsRefused() throws Exception {
        // given — a label and an operation of the client's choosing
        var clientChosenPath = EST_BASE + "client-label/client-operation";
        MockHttpServletRequest request = new MockHttpServletRequest("GET", clientChosenPath);

        // when
        filter.doFilter(request, new MockHttpServletResponse(), filterChain);

        // then
        assertThat(warningsLogged())
                .singleElement(STRING)
                .contains("NOT_FOUND", "GET")
                .doesNotContain("client-label", "client-operation");
    }

    /** Another character where the leading dot or either slash of the EST path belongs must not pass as EST. */
    @ParameterizedTest
    @ValueSource(strings = {
            "/v1/protocols/.well-knownXest/cacerts",
            "/v1/protocols/.well-known/esta/cacerts",
            "/v1/protocols/Xwell-known/est/cacerts"})
    void rejectsWithValidationException_whenPathOnlyLooksLikeTheEstPath(String lookalikePath) throws Exception {
        // given
        MockHttpServletRequest request = new MockHttpServletRequest("GET", CONTEXT + lookalikePath);

        // when
        filter.doFilter(request, new MockHttpServletResponse(), filterChain);

        // then
        verify(resolver, times(1)).resolveException(any(), any(), any(), any(ValidationException.class));
        verify(filterChain, never()).doFilter(any(), any());
        verifyNoInteractions(authHelper);
    }

    @Test
    void passesOn_theRequestAndResponseItReceived() throws Exception {
        // given - a filter that read and discarded the body first, then passed the same (now exhausted) request on,
        // would still satisfy an identity-only check; this reads the body through the chain and expects it intact
        String body = "{\"passphrase\":\"never-copied\"}";
        MockHttpServletRequest request = new MockHttpServletRequest("POST", CONTEXT + "/v1/certificates/search");
        request.setContent(body.getBytes(StandardCharsets.UTF_8));
        MockHttpServletResponse response = new MockHttpServletResponse();
        doAnswer(invocation -> {
            HttpServletRequest chainRequest = invocation.getArgument(0);
            HttpServletResponse chainResponse = invocation.getArgument(1);
            assertThat(chainRequest.getInputStream().readAllBytes()).isEqualTo(body.getBytes(StandardCharsets.UTF_8));
            chainResponse.getWriter().write("downstream-body");
            chainResponse.getWriter().flush();
            return null;
        }).when(filterChain).doFilter(any(), any());

        // when
        filter.doFilter(request, response, filterChain);

        // then - the same objects reached the chain, the request body arrived unread and intact, and the response
        // bytes the chain wrote land on the original response, not a copy
        verify(filterChain).doFilter(same(request), same(response));
        assertThat(response.getContentAsString()).isEqualTo("downstream-body");
    }

    // ── Helpers ───────────────────────────────────────────────────────────────

    private void verifyAuthenticatedAsEstUserBeforeTheChain() throws Exception {
        InOrder inOrder = inOrder(authHelper, filterChain);
        inOrder.verify(authHelper).authenticateAsSystemUser(AuthHelper.EST_USERNAME);
        inOrder.verify(filterChain).doFilter(any(), any());
        verifyNoMoreInteractions(authHelper, filterChain);
        verifyNoInteractions(resolver);
    }

    private void verifyNothingDispatched() {
        verifyNoInteractions(authHelper, filterChain, resolver);
    }

    private List<String> warningsLogged() {
        return logged.list
                .stream()
                .filter(event -> event.getLevel() == Level.WARN)
                .map(ILoggingEvent::getFormattedMessage)
                .toList();
    }

    private static MockHttpServletRequest anEnrollmentRequest(byte[] body) {
        MockHttpServletRequest request = new MockHttpServletRequest("POST", ENROLLMENT_PATH);
        request.setContentType(EstMediaTypes.PKCS10);
        request.setContent(body);
        return request;
    }

    /** An enrollment that, like one with a chunked body, declares no length. */
    private static MockHttpServletRequest aChunkedEnrollmentRequest(byte[] body) {
        MockHttpServletRequest request = new MockHttpServletRequest("POST", ENROLLMENT_PATH) {
            @Override
            public long getContentLengthLong() {
                return -1;
            }
        };
        request.setContentType(EstMediaTypes.PKCS10);
        request.setContent(body);
        return request;
    }

    private static void assertRefusedAs(EstError error, MockHttpServletResponse response) throws Exception {
        assertThat(response.getStatus()).isEqualTo(error.status().value());
        assertThat(MediaType.parseMediaType(response.getContentType())).isEqualTo(PLAIN_TEXT_UTF8);
        assertThat(response.getContentAsString(StandardCharsets.UTF_8)).isEqualTo(error.text());
    }
}
