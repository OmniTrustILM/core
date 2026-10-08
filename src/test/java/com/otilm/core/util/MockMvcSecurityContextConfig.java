package com.otilm.core.util;

import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.boot.webmvc.test.autoconfigure.MockMvcBuilderCustomizer;
import org.springframework.context.annotation.Bean;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.test.web.servlet.MvcResult;

import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.securityContext;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;

/**
 * Security 7's filter chain replaces the thread-bound context a test sets in {@code @BeforeEach} and clears it when the
 * request ends, so each request carries it explicitly and hands it back afterwards. It is read per request, so a test
 * that clears the context still gets 401.
 */
@TestConfiguration(proxyBeanMethods = false)
public class MockMvcSecurityContextConfig {

    private static final String TEST_CONTEXT = MockMvcSecurityContextConfig.class.getName() + ".context";

    @Bean
    MockMvcBuilderCustomizer threadSecurityContextOnEveryRequest() {
        return builder -> {
            builder.defaultRequest(get("/").with(MockMvcSecurityContextConfig::carryThreadContext));
            builder.alwaysDo(MockMvcSecurityContextConfig::restoreThreadContext);
        };
    }

    private static MockHttpServletRequest carryThreadContext(MockHttpServletRequest request) {
        SecurityContext context = SecurityContextHolder.getContext();
        request.setAttribute(TEST_CONTEXT, context);
        return securityContext(context).postProcessRequest(request);
    }

    private static void restoreThreadContext(MvcResult result) {
        SecurityContextHolder.setContext((SecurityContext) result.getRequest().getAttribute(TEST_CONTEXT));
    }
}
