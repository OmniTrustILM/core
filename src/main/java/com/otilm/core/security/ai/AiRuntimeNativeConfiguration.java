package com.otilm.core.security.ai;

import org.springframework.beans.factory.ObjectProvider;
import org.springframework.context.ApplicationContext;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

/** A missing or ambiguous trusted transport leaves native execution unavailable. */
@Configuration(proxyBeanMethods = false)
public class AiRuntimeNativeConfiguration {
    @Bean(destroyMethod = "stop")
    AiRuntimeNativeLifecycle aiRuntimeNativeLifecycle(ObjectProvider<RuntimeProxyTransport> transports,
            ApplicationContext context) {
        RuntimeProxyTransport transport = transports.getIfUnique();
        return new AiRuntimeNativeLifecycle(transport == null ? null : new RuntimeProxyTomcatBinding(transport),
                context);
    }
}
