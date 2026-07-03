package com.otilm.core.integration.events;

import com.otilm.api.exception.EventException;
import com.otilm.api.model.core.auth.Resource;
import com.otilm.api.model.core.discovery.DiscoveryStatus;
import com.otilm.api.model.core.other.ResourceEvent;
import com.otilm.api.model.core.workflows.EventStatus;
import com.otilm.api.model.core.workflows.TriggerType;
import com.otilm.core.dao.entity.DiscoveryHistory;
import com.otilm.core.dao.entity.workflows.EventHistory;
import com.otilm.core.dao.entity.workflows.Trigger;
import com.otilm.core.dao.entity.workflows.TriggerAssociation;
import com.otilm.core.dao.repository.DiscoveryRepository;
import com.otilm.core.dao.repository.workflows.EventHistoryRepository;
import com.otilm.core.dao.repository.workflows.TriggerAssociationRepository;
import com.otilm.core.dao.repository.workflows.TriggerRepository;
import com.otilm.core.events.data.DiscoveryResult;
import com.otilm.core.events.handlers.DiscoveryFinishedEventHandler;
import com.otilm.core.messaging.model.EventMessage;
import com.otilm.core.messaging.model.NotificationMessage;
import com.otilm.core.util.BaseSpringBootTest;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.jms.core.JmsTemplate;
import org.springframework.test.context.bean.override.mockito.MockitoBean;

import java.util.List;
import java.util.UUID;

import static org.mockito.ArgumentMatchers.any;

class EventHistoryTransactionITest extends BaseSpringBootTest {

    @MockitoBean
    JmsTemplate jmsTemplate;

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
     * Verifies that after handleEvent completes: EventHistory is committed with FINISHED status
     * and the notification JMS message is dispatched via the post-commit TransactionalEventListener.
     */
    @Test
    void testEventHistoryVisibleAfterFollowUpNotificationFailure() throws EventException {
        Mockito.doThrow(new RuntimeException("JMS broker unavailable"))
                .when(jmsTemplate).convertAndSend(any(String.class), any(NotificationMessage.class), any());

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
                discoveryUuid, UUID.randomUUID(), null,
                new DiscoveryResult(DiscoveryStatus.COMPLETED, "Test"));
        discoveryFinishedEventHandler.handleEvent(eventMessage);
        Mockito.verify(jmsTemplate).convertAndSend(any(String.class), any(NotificationMessage.class), any());
        // Trigger processing succeeded before the notification throws, EventHistory must be FINISHED,
        // not lost because handleEvent runs without an ambient transaction.
        List<EventHistory> eventHistories = eventHistoryRepository.findAll();
        Assertions.assertEquals(1, eventHistories.size());
        Assertions.assertEquals(EventStatus.FINISHED, eventHistories.getFirst().getStatus());
        Assertions.assertNotNull(eventHistories.getFirst().getFinishedAt());
    }
}
