package com.otilm.core.feasibility;

import com.otilm.core.util.ai.ConversationStreamHttpProofSupport;
import java.util.Map;
import org.springframework.beans.factory.config.BeanFactoryPostProcessor;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.context.annotation.Bean;
import org.springframework.core.env.ConfigurableEnvironment;
import org.springframework.core.env.MapPropertySource;

/** Imported only by local wiring tests; the maintained-stack launcher must not import this configuration. */
@TestConfiguration(proxyBeanMethods = false)
public class ConversationStreamHttpSyntheticAuthConfiguration {
    @Bean
    static BeanFactoryPostProcessor conversationAuthAuthority(ConfigurableEnvironment environment) {
        return beanFactory -> environment
                .getPropertySources()
                .addFirst(new MapPropertySource("f07HttpAuthAuthority",
                        Map.of("auth-service.base-url", ConversationStreamHttpProofSupport.gatewayUrl())));
    }
}
