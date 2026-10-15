package com.otilm.core.config;

import com.otilm.api.exception.ValidationException;
import com.otilm.core.util.AuthHelper;
import jakarta.servlet.FilterChain;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.nio.charset.StandardCharsets;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.test.util.ReflectionTestUtils;
import org.springframework.web.servlet.HandlerExceptionResolver;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.same;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;

/**
 * Unit tests for {@link ProtocolValidationFilter} — the global protocol gate is deny-by-default over
 * {@code /{context}/v*\/protocols/**}. TSP requests are authenticated by the dedicated TSP security chain, so this
 * filter must pass {@code tsp/} through untouched (no system-user authentication, no 422).
 */
@ExtendWith(MockitoExtension.class)
class ProtocolValidationFilterTest {

    private static final String CONTEXT = "/api";

    private ProtocolValidationFilter filter;

    @Mock
    private FilterChain filterChain;

    @Mock
    private HandlerExceptionResolver resolver;

    @Mock
    private AuthHelper authHelper;

    @BeforeEach
    void createFilter() {
        filter = new ProtocolValidationFilter();
        filter.setAuthHelper(authHelper);
        filter.setHandlerExceptionResolver(resolver);
        ReflectionTestUtils.setField(filter, "context", CONTEXT);
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
}
