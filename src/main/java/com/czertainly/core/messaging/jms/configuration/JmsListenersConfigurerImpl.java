package com.czertainly.core.messaging.jms.configuration;

import com.czertainly.core.messaging.jms.listeners.actions.ActionsJmsEndpointConfig;
import com.czertainly.core.messaging.jms.listeners.auditlogs.AuditLogsJmsEndpointConfig;
import com.czertainly.core.messaging.jms.listeners.event.EventJmsEndpointConfig;
import com.czertainly.core.messaging.jms.listeners.notification.NotificationJmsEndpointConfig;
import com.czertainly.core.messaging.jms.listeners.scheduler.SchedulerJmsEndpointConfig;
import com.czertainly.core.messaging.jms.listeners.validation.ValidationJmsEndpointConfig;
import com.czertainly.core.messaging.proxy.InstanceProxyMessageJmsEndpointConfig;
import com.czertainly.core.messaging.proxy.SharedProxyMessageJmsEndpointConfig;
import lombok.AllArgsConstructor;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Profile;
import org.springframework.jms.annotation.JmsListenerConfigurer;
import org.springframework.jms.config.JmsListenerEndpointRegistrar;

import java.util.Optional;

@Configuration
@Profile("!test")
@AllArgsConstructor
public class JmsListenersConfigurerImpl implements JmsListenerConfigurer {

    private final ActionsJmsEndpointConfig actionsJmsEndpointConfig;
    private final AuditLogsJmsEndpointConfig auditLogsJmsEndpointConfig;
    private final EventJmsEndpointConfig eventJmsEndpointConfig;
    private final NotificationJmsEndpointConfig notificationJmsEndpointConfig;
    private final SchedulerJmsEndpointConfig schedulerJmsEndpointConfig;
    private final ValidationJmsEndpointConfig validationJmsEndpointConfig;
    private final Optional<InstanceProxyMessageJmsEndpointConfig> instanceProxyMessageJmsEndpointConfig;
    private final Optional<SharedProxyMessageJmsEndpointConfig> sharedProxyMessageJmsEndpointConfig;

    @Override
    public void configureJmsListeners(JmsListenerEndpointRegistrar registrar) {
        registrar.registerEndpoint(actionsJmsEndpointConfig.listenerEndpoint());
        registrar.registerEndpoint(auditLogsJmsEndpointConfig.listenerEndpoint());
        registrar.registerEndpoint(eventJmsEndpointConfig.listenerEndpoint());
        registrar.registerEndpoint(notificationJmsEndpointConfig.listenerEndpoint());
        registrar.registerEndpoint(schedulerJmsEndpointConfig.listenerEndpoint());
        registrar.registerEndpoint(validationJmsEndpointConfig.listenerEndpoint());
        instanceProxyMessageJmsEndpointConfig.ifPresent(c -> registrar.registerEndpoint(c.listenerEndpoint()));
        sharedProxyMessageJmsEndpointConfig.ifPresent(c -> registrar.registerEndpoint(c.listenerEndpoint()));
    }
}
