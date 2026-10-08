package com.otilm.core.integration.config;

import com.otilm.core.util.BaseSpringBootTest;
import jakarta.servlet.DispatcherType;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.web.servlet.DelegatingFilterProxyRegistrationBean;
import org.springframework.context.ApplicationContext;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * The beans the Boot 3.5 line gets from the session and JMS auto-configuration, which Boot 4 ships in their own
 * modules.
 */
class ProductionAutoConfigurationITest extends BaseSpringBootTest {

    @Autowired
    private ApplicationContext context;

    @Test
    void sessionFilterRunsOnErrorAndAsyncDispatches() {
        DelegatingFilterProxyRegistrationBean registration = context
                .getBean("sessionRepositoryFilterRegistration", DelegatingFilterProxyRegistrationBean.class);
        assertThat(registration.determineDispatcherTypes())
                .containsExactlyInAnyOrder(DispatcherType.ASYNC, DispatcherType.ERROR, DispatcherType.REQUEST);
    }

    @Test
    void brokerCountsTowardsHealth() {
        assertThat(context.containsBean("jmsHealthContributor")).isTrue();
    }
}
