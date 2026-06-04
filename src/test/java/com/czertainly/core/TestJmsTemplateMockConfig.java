package com.czertainly.core;

import org.mockito.Mockito;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Primary;
import org.springframework.context.annotation.Profile;
import org.springframework.jms.core.JmsTemplate;

/**
 * Configuration class for mocking the {@link JmsTemplate} bean during testing.
 * <p>There is also integration branch of tests represented by {@link com.czertainly.core.util.BaseMessagingIntTest} and 'messaging-int-test' profile.</p>

 * This configuration is active when the 'test' profile is enabled, excluding the 'messaging-int-test' profile.
 * It is primarily used to prevent the actual instantiation and use of a real {@link JmsTemplate} during testing scenarios
 * where messaging functionality is not required or needs to be controlled.

 * The {@link JmsTemplate} returned by this configuration is a mocked instance created using {@link Mockito}.
 */
@Configuration
@Profile("test & !messaging-int-test")
public class TestJmsTemplateMockConfig {

    @Bean
    @Primary
    public JmsTemplate testJmsTemplateMock() {
        return Mockito.mock(JmsTemplate.class);
    }
}
