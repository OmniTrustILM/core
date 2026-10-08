package com.otilm.core.util;

import org.mockito.Mockito;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Primary;
import org.springframework.context.annotation.Profile;
import org.springframework.jms.core.JmsTemplate;
import org.springframework.jms.support.converter.MessageConverter;

/**
 * Configuration class for mocking the {@link JmsTemplate} bean during testing.
 * <p>
 * There is also integration branch of tests represented by {@link BaseMessagingIntTest} and 'messaging-int-test'
 * profile.
 * </p>
 *
 * This configuration is active when the 'test' profile is enabled, excluding the 'messaging-int-test' profile. It is
 * primarily used to prevent the actual instantiation and use of a real {@link JmsTemplate} during testing scenarios
 * where messaging functionality is not required or needs to be controlled.
 *
 * The {@link JmsTemplate} returned by this configuration is a mocked instance created using {@link Mockito}.
 */
@Configuration
@Profile("test & !messaging-int-test")
public class TestJmsTemplateMockConfig {

    /** Spring 7's {@code JmsMessagingTemplate}, which Boot builds from this template, reads its converter. */
    @Bean
    @Primary
    public JmsTemplate testJmsTemplateMock(MessageConverter messageConverter) {
        JmsTemplate template = Mockito.mock(JmsTemplate.class);
        Mockito.when(template.getMessageConverter()).thenReturn(messageConverter);
        return template;
    }
}
