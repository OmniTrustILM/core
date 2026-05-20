package com.czertainly.core.events;

import com.czertainly.api.model.core.auth.Resource;
import com.czertainly.api.model.core.discovery.DiscoveryStatus;
import com.czertainly.api.model.core.other.ResourceEvent;
import com.czertainly.api.model.core.workflows.EventStatus;
import com.czertainly.api.model.core.workflows.TriggerType;
import com.czertainly.core.dao.entity.DiscoveryHistory;
import com.czertainly.core.dao.entity.workflows.EventHistory;
import com.czertainly.core.dao.entity.workflows.Trigger;
import com.czertainly.core.dao.entity.workflows.TriggerAssociation;
import com.czertainly.core.dao.repository.DiscoveryRepository;
import com.czertainly.core.dao.repository.workflows.EventHistoryRepository;
import com.czertainly.core.dao.repository.workflows.TriggerAssociationRepository;
import com.czertainly.core.dao.repository.workflows.TriggerRepository;
import com.czertainly.core.events.data.DiscoveryResult;
import com.czertainly.core.events.handlers.DiscoveryFinishedEventHandler;
import com.czertainly.core.messaging.jms.producers.NotificationProducer;
import com.czertainly.core.messaging.model.EventMessage;
import com.czertainly.core.messaging.model.NotificationMessage;
import com.czertainly.core.util.BaseSpringBootTest;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.test.context.bean.override.mockito.MockitoBean;

import java.util.List;
import java.util.UUID;

class EventHistoryTransactionTest extends BaseSpringBootTest {

    @MockitoBean
    NotificationProducer notificationProducer;

    @Autowired
    private EventHistoryRepository eventHistoryRepository;

    @Autowired
    private DiscoveryFinishedEventHandler discoveryFinishedEventHandler;
    @Autowired
    private DiscoveryRepository discoveryRepository;
    @Autowired
    private TriggerRepository triggerRepository;
    @Autowired
    private TriggerAssociationRepository triggerAssociationRepository;

    /**
     * Verifies the end-to-end fix: when sendFollowUpEventsNotifications throws after successful
     * trigger processing, the EventHistory row must still be visible and carry FINISHED status —
     * not rolled back with the enclosing handleEvent invocation, because handleEvent runs with
     * Propagation.NOT_SUPPORTED, and each repository save commits its own small transaction.
     */
    @Test
    void testEventHistoryVisibleAfterFollowUpNotificationFailure() {
        Mockito.doThrow(new RuntimeException("JMS broker unavailable"))
                .when(notificationProducer).produceMessage(Mockito.any(NotificationMessage.class));

        DiscoveryHistory discovery = new DiscoveryHistory();
        discovery.setName("TestDiscovery");
        discovery.setKind("IP");
        discovery.setStatus(DiscoveryStatus.IN_PROGRESS);
        discovery.setConnectorUuid(UUID.randomUUID());
        discovery.setConnectorStatus(DiscoveryStatus.COMPLETED);
        discovery = discoveryRepository.save(discovery);

        // Minimal platform trigger (triggeredBy=null → system user; handleUser is a no-op)
        Trigger trigger = new Trigger();
        trigger.setName("TestTrigger");
        trigger.setType(TriggerType.EVENT);
        trigger.setResource(Resource.DISCOVERY);
        trigger.setEvent(ResourceEvent.DISCOVERY_FINISHED);
        trigger.setIgnoreTrigger(false);
        trigger = triggerRepository.save(trigger);

        TriggerAssociation association = new TriggerAssociation();
        association.setTriggerUuid(trigger.getUuid());
        association.setEvent(ResourceEvent.DISCOVERY_FINISHED);
        // resource and objectUuid left null → platform trigger, matched by fetchEventTriggers(ctx, null, null)
        triggerAssociationRepository.save(association);

        final UUID discoveryUuid = discovery.getUuid();
        EventMessage eventMessage = DiscoveryFinishedEventHandler.constructEventMessage(
                discoveryUuid, null, null,
                new DiscoveryResult(DiscoveryStatus.COMPLETED, "Test"));
        RuntimeException exception = Assertions.assertThrows(RuntimeException.class, () ->
                discoveryFinishedEventHandler.handleEvent(
                        eventMessage));
        Assertions.assertTrue(
                exception.getMessage() != null && exception.getMessage().contains("JMS broker unavailable"),
                "Expected exception to come from mocked follow-up notification failure");

        // Trigger processing succeeded before the notification throws, EventHistory must be FINISHED,
        // not lost because handleEvent runs without an ambient transaction.
        List<EventHistory> eventHistories = eventHistoryRepository.findAll();
        Assertions.assertEquals(1, eventHistories.size());
        Assertions.assertEquals(EventStatus.FINISHED, eventHistories.getFirst().getStatus());
        Assertions.assertNotNull(eventHistories.getFirst().getFinishedAt());
    }
}
