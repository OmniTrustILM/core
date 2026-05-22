package com.czertainly.core.service;

import com.czertainly.api.exception.AlreadyExistException;
import com.czertainly.api.exception.AttributeException;
import com.czertainly.api.exception.NotFoundException;
import com.czertainly.api.model.client.signing.timequality.TimeQualityConfigurationRequestDto;
import com.czertainly.api.model.messaging.timequality.TimeQualityConfig;
import com.czertainly.api.model.messaging.timequality.TimeQualityConfigRequest;
import com.czertainly.api.model.messaging.timequality.TimeQualityConfigSnapshot;
import com.czertainly.core.dao.repository.signing.TimeQualityConfigurationRepository;
import com.czertainly.core.messaging.jms.configuration.MessagingProperties;
import com.czertainly.core.messaging.model.TimeQualityConfigChangedEvent;
import com.czertainly.core.messaging.model.TimeQualityConfigDeletedEvent;
import com.czertainly.core.security.authz.SecuredUUID;
import com.czertainly.core.util.BaseMessagingIntTest;
import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.jms.JMSException;
import jakarta.jms.Message;
import jakarta.jms.TextMessage;
import org.awaitility.Awaitility;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.jms.core.JmsTemplate;
import org.springframework.test.context.event.ApplicationEvents;
import org.springframework.test.context.event.RecordApplicationEvents;

import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;

@RecordApplicationEvents
class TimeQualityConfigurationServiceJmsTest extends BaseMessagingIntTest {

    private static final long DRAIN_TIMEOUT_MS = 200;
    private static final long RECEIVE_TIMEOUT_MS = 5_000;

    @Autowired ApplicationEvents applicationEvents;
    @Autowired TimeQualityConfigurationService service;
    @Autowired TimeQualityConfigurationRepository repository;
    @Autowired JmsTemplate jmsTemplate;
    @Autowired MessagingProperties messagingProperties;
    @Autowired ObjectMapper objectMapper;

    private String configQueueConsumer;
    private String configRequestExchange;

    @BeforeEach
    void prepareEnvironment() {
        configQueueConsumer = messagingProperties.consumerDestination(messagingProperties.queue().timeQualityConfig());
        configRequestExchange = "/exchanges/" + messagingProperties.exchange() + "/"
                + messagingProperties.routingKey().timeQualityConfigRequest();

        // Clean DB so unique-name constraint doesn't carry between tests.
        repository.deleteAll();
        // Drain any pending messages (startup snapshot + leftovers from prior tests).
        drainConfigQueue();
        applicationEvents.clear();
    }

    @Test
    void create_publishesSnapshotContainingNewConfiguration() throws AlreadyExistException, AttributeException, NotFoundException {
        String name = uniqueName("create");

        var created = service.createTimeQualityConfiguration(buildRequest(name));

        TimeQualityConfigSnapshot snapshot = receiveNextSnapshot();
        assertThat(snapshot.getGeneratedAt()).isBefore(Instant.now().plusSeconds(1));
        assertThat(snapshot.getCorrelationId()).isNull();
        assertThat(snapshot.getConfigurations()).hasSize(1);

        TimeQualityConfig published = snapshot.getConfigurations().getFirst();
        assertThat(published.getId()).isEqualTo(UUID.fromString(created.getUuid()));
        assertThat(published.getName()).isEqualTo(name);
        assertThat(published.getNtpServers()).containsExactly("pool.ntp.org");
        assertThat(published.getMaxClockDrift()).isEqualTo(Duration.ofSeconds(1));
        assertThat(published.isLeapSecondGuard()).isTrue();

        assertThat(applicationEvents.stream(TimeQualityConfigChangedEvent.class)).hasSize(1);
    }

    @Test
    void update_publishesSnapshotContainingUpdatedConfiguration() throws AlreadyExistException, AttributeException, NotFoundException {
        var created = service.createTimeQualityConfiguration(buildRequest(uniqueName("update-pre")));
        drainConfigQueue();
        applicationEvents.clear();

        String renamed = uniqueName("update-post");
        service.updateTimeQualityConfiguration(SecuredUUID.fromString(created.getUuid()), buildRequest(renamed));

        TimeQualityConfigSnapshot snapshot = receiveNextSnapshot();
        assertThat(snapshot.getConfigurations()).hasSize(1);
        assertThat(snapshot.getConfigurations().getFirst().getId()).isEqualTo(UUID.fromString(created.getUuid()));
        assertThat(snapshot.getConfigurations().getFirst().getName()).isEqualTo(renamed);

        assertThat(applicationEvents.stream(TimeQualityConfigChangedEvent.class)).hasSize(1);
    }

    @Test
    void delete_publishesEmptySnapshotAndFiresDeletedEventWithUuid() throws AlreadyExistException, AttributeException, NotFoundException {
        var created = service.createTimeQualityConfiguration(buildRequest(uniqueName("delete")));
        drainConfigQueue();
        applicationEvents.clear();

        UUID configurationId = UUID.fromString(created.getUuid());
        service.deleteTimeQualityConfiguration(SecuredUUID.fromString(created.getUuid()));

        TimeQualityConfigSnapshot snapshot = receiveNextSnapshot();
        assertThat(snapshot.getConfigurations()).isEmpty();

        // Both in-process events must fire so the local register and external monitor stay aligned.
        assertThat(applicationEvents.stream(TimeQualityConfigChangedEvent.class)).hasSize(1);
        assertThat(applicationEvents.stream(TimeQualityConfigDeletedEvent.class)
                .map(TimeQualityConfigDeletedEvent::getConfigurationId))
                .containsExactly(configurationId);
    }

    @Test
    void bulkDelete_publishesSnapshotPerDeletionAndFiresDeletedEventPerEntry() throws AlreadyExistException, AttributeException, NotFoundException {
        var a = service.createTimeQualityConfiguration(buildRequest(uniqueName("bulk-a")));
        var b = service.createTimeQualityConfiguration(buildRequest(uniqueName("bulk-b")));
        var c = service.createTimeQualityConfiguration(buildRequest(uniqueName("bulk-c")));
        drainConfigQueue();
        applicationEvents.clear();

        var failures = service.bulkDeleteTimeQualityConfigurations(List.of(
                SecuredUUID.fromString(a.getUuid()),
                SecuredUUID.fromString(b.getUuid()),
                SecuredUUID.fromString(c.getUuid())
        ));

        assertThat(failures).isEmpty();

        // Each delete runs in its own transaction, so we receive three snapshots
        // and the final one is empty. This is the high-risk path the original
        // unit test did not cover (Spring's @Transactional on a package-private
        // method silently dropping the events would surface here).
        List<TimeQualityConfigSnapshot> snapshots = receiveSnapshots(3);
        assertThat(snapshots).hasSize(3);
        assertThat(snapshots.get(0).getConfigurations()).hasSize(2);
        assertThat(snapshots.get(1).getConfigurations()).hasSize(1);
        assertThat(snapshots.get(2).getConfigurations()).isEmpty();

        assertThat(applicationEvents.stream(TimeQualityConfigChangedEvent.class)).hasSize(3);
        assertThat(applicationEvents.stream(TimeQualityConfigDeletedEvent.class)
                .map(TimeQualityConfigDeletedEvent::getConfigurationId))
                .containsExactlyInAnyOrder(
                        UUID.fromString(a.getUuid()),
                        UUID.fromString(b.getUuid()),
                        UUID.fromString(c.getUuid()));
    }

    @Test
    void configRequest_triggersSnapshotResponseCarryingCorrelationId() throws AlreadyExistException, AttributeException, NotFoundException {
        var created = service.createTimeQualityConfiguration(buildRequest(uniqueName("resync")));
        drainConfigQueue();

        UUID correlationId = UUID.randomUUID();
        TimeQualityConfigRequest request = new TimeQualityConfigRequest();
        request.setCorrelationId(correlationId);
        request.setRequestedAt(Instant.now());
        sendConfigRequest(request);

        TimeQualityConfigSnapshot response = Awaitility.await()
                .atMost(Duration.ofSeconds(10))
                .pollInterval(Duration.ofMillis(200))
                .until(this::receiveSnapshotIfAvailable, snapshot -> snapshot != null && correlationId.equals(snapshot.getCorrelationId()));

        assertThat(response.getConfigurations()).hasSize(1);
        assertThat(response.getConfigurations().getFirst().getId()).isEqualTo(UUID.fromString(created.getUuid()));
    }

    // ──────────────────────────────────────────────────────────────────────────
    // Helpers
    // ──────────────────────────────────────────────────────────────────────────

    private TimeQualityConfigurationRequestDto buildRequest(String name) {
        TimeQualityConfigurationRequestDto r = new TimeQualityConfigurationRequestDto();
        r.setName(name);
        r.setAccuracy(Duration.ofSeconds(1));
        r.setNtpServers(List.of("pool.ntp.org"));
        r.setNtpCheckInterval(Duration.ofSeconds(30));
        r.setNtpSamplesPerServer(4);
        r.setNtpCheckTimeout(Duration.ofSeconds(5));
        r.setNtpServersMinReachable(1);
        r.setMaxClockDrift(Duration.ofSeconds(1));
        r.setLeapSecondGuard(true);
        return r;
    }

    private String uniqueName(String prefix) {
        return prefix + "-" + UUID.randomUUID();
    }

    private TimeQualityConfigSnapshot receiveNextSnapshot() {
        TimeQualityConfigSnapshot received = receiveSnapshotWithTimeout(RECEIVE_TIMEOUT_MS);
        assertThat(received)
                .as("Expected a TimeQualityConfigSnapshot on %s within %dms", configQueueConsumer, RECEIVE_TIMEOUT_MS)
                .isNotNull();
        return received;
    }

    private TimeQualityConfigSnapshot receiveSnapshotIfAvailable() {
        return receiveSnapshotWithTimeout(DRAIN_TIMEOUT_MS);
    }

    private List<TimeQualityConfigSnapshot> receiveSnapshots(int expected) {
        return java.util.stream.Stream
                .generate(this::receiveNextSnapshot)
                .limit(expected)
                .toList();
    }

    private void drainConfigQueue() {
        while (receiveSnapshotWithTimeout(DRAIN_TIMEOUT_MS) != null) {
            // discard
        }
    }

    /**
     * Production listeners do not use the JMS message converter — they read the
     * raw TextMessage body and deserialize with ObjectMapper to a known class
     * (see AbstractJmsEndpointConfig). We mirror that pattern here so the test
     * uses the same deserialization contract as the receivers in production.
     */
    private TimeQualityConfigSnapshot receiveSnapshotWithTimeout(long timeoutMs) {
        long previous = jmsTemplate.getReceiveTimeout();
        jmsTemplate.setReceiveTimeout(timeoutMs);
        try {
            Message message = jmsTemplate.receive(configQueueConsumer);
            if (message == null) {
                return null;
            }
            if (!(message instanceof TextMessage textMessage)) {
                throw new IllegalStateException("Expected TextMessage but got: " + message.getClass().getName());
            }
            return objectMapper.readValue(textMessage.getText(), TimeQualityConfigSnapshot.class);
        } catch (JMSException | com.fasterxml.jackson.core.JsonProcessingException e) {
            throw new IllegalStateException("Failed to receive/deserialize snapshot", e);
        } finally {
            jmsTemplate.setReceiveTimeout(previous);
        }
    }

    private void sendConfigRequest(TimeQualityConfigRequest request) {
        jmsTemplate.convertAndSend(configRequestExchange, request, msg -> {
            msg.setJMSType(messagingProperties.routingKey().timeQualityConfigRequest());
            return msg;
        });
    }
}
