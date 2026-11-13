package com.otilm.core.util;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * The assertions pin the public path EST clients are given, so a change here is a change to the client-facing contract.
 */
class EstProtocolUrlFactoryTest {

    // ── ForLabel ──────────────────────────────────────────────────────────────

    @Nested
    class ForLabel {

        @Test
        void returnsUrlUnderTheWellKnownPath() {
            // given
            var origin = "https://ilm.example.com";
            var label = "devices";

            // when
            String url = EstProtocolUrlFactory.forLabel(origin, label);

            // then
            assertThat(url).isEqualTo(origin + "/.well-known/est/" + label);
        }
    }

    // ── CurrentOrigin ─────────────────────────────────────────────────────────

    @Nested
    class CurrentOrigin {

        @AfterEach
        void clearRequestContext() {
            RequestContextHolder.resetRequestAttributes();
        }

        @Test
        void returnsOriginWithoutContextPath_whenRequestIsServedUnderOne() {
            // given
            var contextPath = "/api";
            bindRequest("https", "ilm.example.com", 443, contextPath);

            // when
            String origin = EstProtocolUrlFactory.currentOrigin();

            // then
            assertThat(origin).isEqualTo("https://ilm.example.com");
        }

        @Test
        void returnsOriginWithPort_whenPortIsNotTheDefault() {
            // given
            var nonDefaultPort = 8443;
            bindRequest("https", "ilm.example.com", nonDefaultPort, "/api");

            // when
            String origin = EstProtocolUrlFactory.currentOrigin();

            // then
            assertThat(origin).isEqualTo("https://ilm.example.com:" + nonDefaultPort);
        }

        // ── Helpers ───────────────────────────────────────────────────────────

        private static void bindRequest(String scheme, String host, int port, String contextPath) {
            MockHttpServletRequest request = new MockHttpServletRequest();
            request.setScheme(scheme);
            request.setServerName(host);
            request.setServerPort(port);
            request.setContextPath(contextPath);
            RequestContextHolder.setRequestAttributes(new ServletRequestAttributes(request));
        }
    }
}
