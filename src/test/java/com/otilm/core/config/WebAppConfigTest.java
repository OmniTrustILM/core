package com.otilm.core.config;

import com.otilm.core.config.logging.MdcRequestFilter;
import org.junit.jupiter.api.Test;
import org.springframework.boot.autoconfigure.security.SecurityProperties;
import org.springframework.boot.web.servlet.FilterRegistrationBean;

import static org.assertj.core.api.Assertions.assertThat;

class WebAppConfigTest {

    /** The MDC boundary encloses the Spring Security chains, whose authentication names the actor in the MDC. */
    @Test
    void mdcRequestFilter_enclosesTheSecurityChainsOnEveryPath() {
        // when
        FilterRegistrationBean<MdcRequestFilter> registration = new WebAppConfig().mdcRequestFilter();

        // then
        assertThat(registration.getFilter()).isInstanceOf(MdcRequestFilter.class);
        assertThat(registration.getUrlPatterns()).containsExactly("/*");
        assertThat(registration.getOrder()).isLessThan(SecurityProperties.DEFAULT_FILTER_ORDER);
    }
}
