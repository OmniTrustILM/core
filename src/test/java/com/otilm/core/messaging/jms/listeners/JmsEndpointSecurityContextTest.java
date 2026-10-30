package com.otilm.core.messaging.jms.listeners;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.otilm.core.messaging.jms.configuration.MessagingProperties;
import jakarta.jms.TextMessage;
import java.util.ArrayList;
import java.util.List;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.springframework.jms.config.SimpleJmsListenerEndpoint;
import org.springframework.retry.support.RetryTemplate;
import org.springframework.security.authentication.TestingAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/**
 * A container thread serves many messages in sequence, so an identity installed for one must not outlive it — otherwise
 * the next message's JPA-audited rows are stamped under a previous message's user.
 */
class JmsEndpointSecurityContextTest {

    private final List<Authentication> authenticationSeenAtEntry = new ArrayList<>();

    @AfterEach
    void clearLeftoverContext() {
        SecurityContextHolder.clearContext();
    }

    @Test
    void securityContextIsClearedAfterMessageIsProcessed() throws Exception {
        SimpleJmsListenerEndpoint endpoint = endpointWithProcessor(
                message -> SecurityContextHolder.getContext().setAuthentication(authenticationFor("discovery-user")));

        endpoint.getMessageListener().onMessage(textMessage("\"first\""));

        assertThat(SecurityContextHolder.getContext().getAuthentication()).isNull();
    }

    @Test
    void identityFromOneMessageDoesNotLeakIntoTheNext() throws Exception {
        SimpleJmsListenerEndpoint endpoint = endpointWithProcessor(message -> {
            authenticationSeenAtEntry.add(SecurityContextHolder.getContext().getAuthentication());
            SecurityContextHolder.getContext().setAuthentication(authenticationFor("discovery-user"));
        });

        endpoint.getMessageListener().onMessage(textMessage("\"first\""));
        endpoint.getMessageListener().onMessage(textMessage("\"second\""));

        assertThat(authenticationSeenAtEntry).hasSize(2);
        assertThat(authenticationSeenAtEntry.get(0)).isNull();
        assertThat(authenticationSeenAtEntry.get(1))
                .as("second message must not inherit the identity installed while handling the first")
                .isNull();
    }

    @Test
    void securityContextIsClearedEvenWhenTheHandlerThrows() throws Exception {
        SimpleJmsListenerEndpoint endpoint = endpointWithProcessor(message -> {
            SecurityContextHolder.getContext().setAuthentication(authenticationFor("discovery-user"));
            throw new IllegalStateException("handler blew up");
        });

        endpoint.getMessageListener().onMessage(textMessage("\"first\""));

        assertThat(SecurityContextHolder.getContext().getAuthentication()).isNull();
    }

    private SimpleJmsListenerEndpoint endpointWithProcessor(MessageProcessor<String> processor) {
        MessagingProperties properties = mock(MessagingProperties.class);
        when(properties.brokerType()).thenReturn(MessagingProperties.BrokerType.RABBITMQ);

        AbstractJmsEndpointConfig<String> config = new AbstractJmsEndpointConfig<>(new ObjectMapper(), processor,
                new RetryTemplate(), properties) {
            @Override
            public SimpleJmsListenerEndpoint listenerEndpoint() {
                return listenerEndpointInternal("testListener", "/queues/test", "test", null, "1", String.class);
            }
        };

        return config.listenerEndpoint();
    }

    private TextMessage textMessage(String json) throws Exception {
        TextMessage message = mock(TextMessage.class);
        when(message.getText()).thenReturn(json);
        return message;
    }

    private Authentication authenticationFor(String username) {
        return new TestingAuthenticationToken(username, "n/a");
    }
}
