package com.otilm.core.messaging.jms.listeners;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.otilm.api.model.core.auth.Resource;
import com.otilm.api.model.core.logging.enums.ActorType;
import com.otilm.api.model.core.other.ResourceEvent;
import com.otilm.core.logging.LoggingHelper;
import com.otilm.core.messaging.jms.configuration.MessagingConcurrencyProperties;
import com.otilm.core.messaging.jms.configuration.MessagingProperties;
import com.otilm.core.messaging.jms.configuration.RetryConfig;
import com.otilm.core.messaging.jms.listeners.event.EventJmsEndpointConfig;
import com.otilm.core.messaging.model.EventMessage;
import jakarta.jms.ConnectionFactory;
import jakarta.jms.JMSException;
import jakarta.jms.Message;
import jakarta.jms.Session;
import jakarta.jms.TextMessage;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.stream.Stream;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;
import org.junit.jupiter.params.provider.MethodSource;
import org.junit.jupiter.params.provider.ValueSource;
import org.springframework.dao.DataAccessResourceFailureException;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.dao.RecoverableDataAccessException;
import org.springframework.dao.TransientDataAccessResourceException;
import org.springframework.jms.config.SimpleJmsListenerEndpoint;
import org.springframework.jms.listener.DefaultMessageListenerContainer;
import org.springframework.retry.support.RetryTemplate;
import org.springframework.security.authentication.TestingAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.transaction.CannotCreateTransactionException;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

class EventJmsEndpointConfigTest {

    private final ObjectMapper mapper = new ObjectMapper();

    @AfterEach
    void clearContext() {
        SecurityContextHolder.clearContext();
        LoggingHelper.clearActorInfo();
    }

    @Test
    void databaseFailureRetriesWithTheActingIdentityClearedBetweenAttempts() throws Exception {
        AtomicInteger attempts = new AtomicInteger();
        List<Authentication> entryIdentities = new ArrayList<>();
        List<Boolean> entryActors = new ArrayList<>();
        SimpleJmsListenerEndpoint endpoint = endpoint(MessagingProperties.BrokerType.RABBITMQ, message -> {
            entryIdentities.add(SecurityContextHolder.getContext().getAuthentication());
            entryActors.add(LoggingHelper.hasActorInfo());
            SecurityContextHolder.getContext().setAuthentication(new TestingAuthenticationToken("actor", "n/a"));
            LoggingHelper.putActorInfoWhenNull(ActorType.USER, "actor", null);
            if (attempts.incrementAndGet() < 3) {
                throw new DataAccessResourceFailureException("Database unavailable");
            }
        });

        endpoint.getMessageListener().onMessage(validMessage());

        assertThat(attempts).hasValue(3);
        assertThat(entryIdentities).containsExactly(null, null, null);
        assertThat(entryActors).containsExactly(false, false, false);
        assertThat(SecurityContextHolder.getContext().getAuthentication()).isNull();
        assertThat(LoggingHelper.snapshotActorInfo().values()).allSatisfy(value -> assertThat(value).isNull());
    }

    @ParameterizedTest
    @MethodSource("infrastructureFailures")
    void infrastructureFailureRetriesUntilProcessingSucceeds(RuntimeException failure) throws Exception {
        AtomicInteger attempts = new AtomicInteger();
        SimpleJmsListenerEndpoint endpoint = endpoint(MessagingProperties.BrokerType.RABBITMQ, message -> {
            if (attempts.incrementAndGet() < 3) {
                throw failure;
            }
        });

        endpoint.getMessageListener().onMessage(validMessage());

        assertThat(attempts).hasValue(3);
    }

    private static Stream<RuntimeException> infrastructureFailures() {
        return Stream
                .of(new DataAccessResourceFailureException("Database unavailable"),
                        new TransientDataAccessResourceException("Database temporarily unavailable"),
                        new RecoverableDataAccessException("Connection must be restored"),
                        new CannotCreateTransactionException("Connection pool unavailable"));
    }

    @ParameterizedTest
    @EnumSource(MessagingProperties.BrokerType.class)
    void retryExhaustionReturnsTheMessageToTheBroker(MessagingProperties.BrokerType broker) throws Exception {
        AtomicInteger attempts = new AtomicInteger();
        DataAccessResourceFailureException unavailable = new DataAccessResourceFailureException("Database unavailable");
        ExecutingContainer container = container(broker, message -> {
            attempts.incrementAndGet();
            throw unavailable;
        });
        Session session = sessionFor(container);
        TextMessage message = validMessage();

        assertThatThrownBy(() -> container.deliver(session, message)).isSameAs(unavailable);

        assertThat(attempts).hasValue(3);
        verify(message, never()).acknowledge();
        verify(session, never()).commit();
        if (broker == MessagingProperties.BrokerType.RABBITMQ) {
            assertThat(container.isSessionTransacted()).isFalse();
            verify(session).recover();
            verify(session, never()).rollback();
        } else {
            verify(session).rollback();
            verify(session, never()).recover();
        }
    }

    @ParameterizedTest
    @EnumSource(MessagingProperties.BrokerType.class)
    void malformedPayloadCompletesWithoutPoisonRedelivery(MessagingProperties.BrokerType broker) throws Exception {
        AtomicInteger processed = new AtomicInteger();
        ExecutingContainer container = container(broker, message -> processed.incrementAndGet());
        Session session = sessionFor(container);
        TextMessage malformed = textMessage("{invalid");

        assertThatCode(() -> container.deliver(session, malformed)).doesNotThrowAnyException();

        assertThat(processed).hasValue(0);
        verify(malformed).getText();
        assertAcknowledged(broker, session, malformed);
    }

    @Test
    void dataIntegrityFailureIsTerminal() throws Exception {
        AtomicInteger attempts = new AtomicInteger();
        ExecutingContainer container = container(MessagingProperties.BrokerType.RABBITMQ, message -> {
            attempts.incrementAndGet();
            throw new DataIntegrityViolationException("Invalid event state");
        });
        Session session = sessionFor(container);
        TextMessage message = validMessage();

        assertThatCode(() -> container.deliver(session, message)).doesNotThrowAnyException();

        assertThat(attempts).hasValue(1);
        assertAcknowledged(MessagingProperties.BrokerType.RABBITMQ, session, message);
    }

    @ParameterizedTest
    @ValueSource(strings = {"null", "{}", "{\"event\":\"cbom_synced\"}", " "})
    void incompleteEventPayloadIsTerminal(String payload) throws Exception {
        AtomicInteger processed = new AtomicInteger();
        ExecutingContainer container = container(MessagingProperties.BrokerType.RABBITMQ,
                message -> processed.incrementAndGet());
        Session session = sessionFor(container);
        TextMessage invalid = textMessage(payload);

        assertThatCode(() -> container.deliver(session, invalid)).doesNotThrowAnyException();

        assertThat(processed).hasValue(0);
        verify(invalid).getText();
        assertAcknowledged(MessagingProperties.BrokerType.RABBITMQ, session, invalid);
    }

    @Test
    void unexpectedHandlerFailureEscapesToTheContainer() throws Exception {
        IllegalStateException failure = new IllegalStateException("Unexpected handler failure");
        ExecutingContainer container = container(MessagingProperties.BrokerType.RABBITMQ, message -> {
            throw failure;
        });
        Session session = sessionFor(container);
        TextMessage message = validMessage();

        assertThatThrownBy(() -> container.deliver(session, message)).isSameAs(failure);

        verify(session).recover();
        verify(message, never()).acknowledge();
    }

    private void assertAcknowledged(MessagingProperties.BrokerType broker, Session session, TextMessage message)
            throws JMSException {
        verify(session, never()).recover();
        verify(session, never()).rollback();
        if (broker == MessagingProperties.BrokerType.RABBITMQ) {
            verify(message).acknowledge();
        } else {
            verify(session).commit();
        }
    }

    private ExecutingContainer container(MessagingProperties.BrokerType broker,
            MessageProcessor<EventMessage> processor) {
        ExecutingContainer container = new ExecutingContainer();
        container.setConnectionFactory(mock(ConnectionFactory.class));
        container.setAcceptMessagesWhileStopping(true);
        endpoint(broker, processor).setupListenerContainer(container);
        return container;
    }

    private Session sessionFor(ExecutingContainer container) throws JMSException {
        Session session = mock(Session.class);
        when(session.getTransacted()).thenReturn(container.isSessionTransacted());
        when(session.getAcknowledgeMode()).thenReturn(container.getSessionAcknowledgeMode());
        return session;
    }

    private SimpleJmsListenerEndpoint endpoint(MessagingProperties.BrokerType broker,
            MessageProcessor<EventMessage> processor) {
        MessagingProperties properties = mock(MessagingProperties.class);
        when(properties.brokerType()).thenReturn(broker);
        when(properties.queue())
                .thenReturn(new MessagingProperties.Queue("actions", "audit", "events", "notifications", "scheduler",
                        "validation", "time.config-request", "time.config", "time.results", "poll", "discovery"));
        when(properties.routingKey())
                .thenReturn(new MessagingProperties.RoutingKey("action", "audit", "event", "notification", "scheduler",
                        "validation", "time.config-request", "time.config", "time.results", "poll", "discovery"));
        when(properties.consumerDestination("events"))
                .thenReturn(broker == MessagingProperties.BrokerType.RABBITMQ ? "/queues/events" : "ilm");
        when(properties.producer())
                .thenReturn(new MessagingProperties.Producer(new MessagingProperties.Retry(true, 1L, 3, 1L, 1L)));
        RetryTemplate retry = new RetryConfig().eventRetryTemplate(properties);
        MessagingConcurrencyProperties concurrency = new MessagingConcurrencyProperties("1", "1", "1", "1", "1", "1",
                "1", "1", "1", "1");
        return new EventJmsEndpointConfig(mapper, processor, retry, properties, concurrency).listenerEndpoint();
    }

    private TextMessage validMessage() throws Exception {
        return textMessage(mapper
                .writeValueAsString(
                        new EventMessage(ResourceEvent.CBOM_SYNCED, Resource.CBOM, UUID.randomUUID(), null)));
    }

    private TextMessage textMessage(String body) throws JMSException {
        TextMessage message = mock(TextMessage.class);
        when(message.getText()).thenReturn(body);
        return message;
    }

    private static final class ExecutingContainer extends DefaultMessageListenerContainer {
        void deliver(Session session, Message message) throws JMSException {
            doExecuteListener(session, message);
        }
    }
}
