package com.czertainly.core.service;

import com.czertainly.api.exception.AlreadyExistException;
import com.czertainly.api.exception.NotFoundException;
import com.czertainly.api.exception.ValidationException;
import com.czertainly.api.model.client.notification.NotificationProfileRequestDto;
import com.czertainly.api.model.common.PaginationResponseDto;
import com.czertainly.api.model.core.auth.Resource;
import com.czertainly.api.model.core.certificate.CertificateState;
import com.czertainly.api.model.core.certificate.CertificateValidationStatus;
import com.czertainly.api.model.core.notification.RecipientType;
import com.czertainly.api.model.core.other.ResourceEvent;
import com.czertainly.api.model.core.scheduler.PaginationRequestDto;
import com.czertainly.api.model.core.workflows.*;
import com.czertainly.core.dao.entity.Certificate;
import com.czertainly.core.dao.entity.CertificateContent;
import com.czertainly.core.dao.entity.workflows.EventHistory;
import com.czertainly.core.dao.entity.workflows.TriggerHistory;
import com.czertainly.core.dao.repository.CertificateContentRepository;
import com.czertainly.core.dao.repository.CertificateRepository;
import com.czertainly.core.dao.repository.workflows.EventHistoryRepository;
import com.czertainly.core.dao.repository.workflows.TriggerHistoryRepository;
import com.czertainly.core.util.BaseSpringBootTest;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;

import java.time.OffsetDateTime;
import java.time.temporal.ChronoUnit;
import java.util.List;
import java.util.UUID;

class EventServiceTest extends BaseSpringBootTest {

    @Autowired
    private EventService eventService;

    @Autowired
    private TriggerService triggerService;

    @Autowired
    private ActionService actionService;

    @Autowired
    private NotificationProfileService notificationProfileService;

    @Autowired
    private CertificateRepository certificateRepository;

    @Autowired
    private CertificateContentRepository certificateContentRepository;

    @Autowired
    private EventHistoryRepository eventHistoryRepository;

    @Autowired
    private TriggerHistoryRepository triggerHistoryRepository;

    // trigger with SEND_NOTIFICATION execution — used to verify notificationsSent logic
    private UUID triggerWithNotificationUuid;
    // ignore trigger — used to verify objectsIgnored count
    private UUID ignoreTriggerUuid;

    // UUID of the certificate created in setUp — used as both EventHistory.resourceUuid
    // and the object UUID in trigger histories for object-level tests
    private UUID certificateUuid;
    private EventHistory savedEventHistory;

    @BeforeEach
    void setUp() throws AlreadyExistException, NotFoundException {
        certificateUuid = createCertificate();

        // notification profile (minimal, no actual dispatch)
        NotificationProfileRequestDto profileRequest = new NotificationProfileRequestDto();
        profileRequest.setName("TestProfile");
        profileRequest.setRecipientType(RecipientType.NONE);
        profileRequest.setRepetitions(1);
        profileRequest.setInternalNotification(true);
        String notificationProfileUuid = notificationProfileService.createNotificationProfile(profileRequest).getUuid();

        // SEND_NOTIFICATION execution
        ExecutionItemRequestDto executionItemRequest = new ExecutionItemRequestDto();
        executionItemRequest.setNotificationProfileUuid(notificationProfileUuid);
        ExecutionRequestDto executionRequest = new ExecutionRequestDto();
        executionRequest.setName("TestSendNotificationExecution");
        executionRequest.setResource(Resource.CERTIFICATE);
        executionRequest.setType(ExecutionType.SEND_NOTIFICATION);
        executionRequest.setItems(List.of(executionItemRequest));
        String executionUuid = actionService.createExecution(executionRequest).getUuid();

        // action
        ActionRequestDto actionRequest = new ActionRequestDto();
        actionRequest.setName("TestAction");
        actionRequest.setResource(Resource.CERTIFICATE);
        actionRequest.setExecutionsUuids(List.of(executionUuid));
        String actionUuid = actionService.createAction(actionRequest).getUuid();

        // regular trigger (with SEND_NOTIFICATION action)
        TriggerRequestDto triggerRequest = new TriggerRequestDto();
        triggerRequest.setName("TestTrigger");
        triggerRequest.setResource(Resource.CERTIFICATE);
        triggerRequest.setType(TriggerType.EVENT);
        triggerRequest.setEvent(ResourceEvent.CERTIFICATE_DISCOVERED);
        triggerRequest.setActionsUuids(List.of(actionUuid));
        triggerWithNotificationUuid = UUID.fromString(triggerService.createTrigger(triggerRequest).getUuid());

        // ignore trigger (no actions allowed)
        TriggerRequestDto ignoreTriggerRequest = new TriggerRequestDto();
        ignoreTriggerRequest.setName("TestIgnoreTrigger");
        ignoreTriggerRequest.setResource(Resource.CERTIFICATE);
        ignoreTriggerRequest.setType(TriggerType.EVENT);
        ignoreTriggerRequest.setEvent(ResourceEvent.CERTIFICATE_DISCOVERED);
        ignoreTriggerRequest.setIgnoreTrigger(true);
        ignoreTriggerUuid = UUID.fromString(triggerService.createTrigger(ignoreTriggerRequest).getUuid());

        // event history for CERTIFICATE_DISCOVERED on certificateUuid
        EventHistory eventHistory = new EventHistory();
        eventHistory.setUuid(UUID.randomUUID());
        eventHistory.setEvent(ResourceEvent.CERTIFICATE_DISCOVERED);
        eventHistory.setResource(Resource.CERTIFICATE);
        eventHistory.setResourceUuid(certificateUuid);
        eventHistory.setStartedAt(OffsetDateTime.now().minusMinutes(2));
        eventHistory.setFinishedAt(OffsetDateTime.now().minusMinutes(1));
        eventHistory.setStatus(EventStatus.FINISHED);
        savedEventHistory = eventHistoryRepository.save(eventHistory);
    }

    // ── getEventHistory(Resource, UUID, PaginationRequestDto) ─────────────────

    @Test
    void testGetObjectEventHistoryEmpty() throws NotFoundException {
        // certificate exists but has no trigger histories linked to it
        PaginationResponseDto<ObjectEventHistoryDto> response =
                eventService.getEventHistory(Resource.CERTIFICATE, certificateUuid, pagination(10, 1));

        Assertions.assertEquals(0, response.getTotalItems());
        Assertions.assertEquals(0, response.getTotalPages());
        Assertions.assertTrue(response.getItems().isEmpty());
    }

    @Test
    void testGetObjectEventHistoryReturnsTriggerHistory() throws NotFoundException {
        TriggerHistory th = saveTriggerHistory(triggerWithNotificationUuid, certificateUuid, savedEventHistory, true, true);

        PaginationResponseDto<ObjectEventHistoryDto> response =
                eventService.getEventHistory(Resource.CERTIFICATE, certificateUuid, pagination(10, 1));

        Assertions.assertEquals(1, response.getTotalItems());
        ObjectEventHistoryDto dto = response.getItems().getFirst();
        Assertions.assertEquals(ResourceEvent.CERTIFICATE_DISCOVERED, dto.getEvent());
        Assertions.assertTrue(dto.isConditionsMatched());
        Assertions.assertTrue(dto.isActionsPerformed());
        th = triggerHistoryRepository.findById(th.getUuid()).orElseThrow();
        Assertions.assertTrue(th.getTriggeredAt().truncatedTo(ChronoUnit.MICROS).isEqual(dto.getTriggeredAt().truncatedTo(ChronoUnit.MICROS)));

    }

    @Test
    void testGetObjectEventHistoryPagination() throws NotFoundException {
        saveTriggerHistory(triggerWithNotificationUuid, certificateUuid, savedEventHistory, true, true);
        saveTriggerHistory(triggerWithNotificationUuid, certificateUuid, savedEventHistory, false, false);
        saveTriggerHistory(ignoreTriggerUuid, certificateUuid, savedEventHistory, true, false);

        PaginationResponseDto<ObjectEventHistoryDto> page1 =
                eventService.getEventHistory(Resource.CERTIFICATE, certificateUuid, pagination(2, 1));
        Assertions.assertEquals(3, page1.getTotalItems());
        Assertions.assertEquals(2, page1.getItems().size());

        PaginationResponseDto<ObjectEventHistoryDto> page2 =
                eventService.getEventHistory(Resource.CERTIFICATE, certificateUuid, pagination(2, 2));
        Assertions.assertEquals(3, page2.getTotalItems());
        Assertions.assertEquals(1, page2.getItems().size());
    }

    @Test
    void testGetObjectEventHistoryNotificationsSentTrue() throws NotFoundException {
        // conditionsMatched=true and no failed SEND_NOTIFICATION records → notificationsSent=true
        saveTriggerHistory(triggerWithNotificationUuid, certificateUuid, savedEventHistory, true, true);

        PaginationResponseDto<ObjectEventHistoryDto> response =
                eventService.getEventHistory(Resource.CERTIFICATE, certificateUuid, pagination(10, 1));

        Assertions.assertEquals(Boolean.TRUE, response.getItems().getFirst().getNotificationsSent());
    }

    @Test
    void testGetObjectEventHistoryNotificationsSentFalseWhenConditionsNotMatched() throws NotFoundException {
        // conditionsMatched=false → notificationsSent=false
        saveTriggerHistory(triggerWithNotificationUuid, certificateUuid, savedEventHistory, false, false);

        PaginationResponseDto<ObjectEventHistoryDto> response =
                eventService.getEventHistory(Resource.CERTIFICATE, certificateUuid, pagination(10, 1));

        Assertions.assertEquals(Boolean.FALSE, response.getItems().getFirst().getNotificationsSent());
    }

    @Test
    void testGetObjectEventHistoryNotificationsSentNullWhenNoNotificationExecution() throws NotFoundException {
        // ignore trigger has no SEND_NOTIFICATION execution → notificationsSent=null
        saveTriggerHistory(ignoreTriggerUuid, certificateUuid, savedEventHistory, true, false);

        PaginationResponseDto<ObjectEventHistoryDto> response =
                eventService.getEventHistory(Resource.CERTIFICATE, certificateUuid, pagination(10, 1));

        Assertions.assertNull(response.getItems().getFirst().getNotificationsSent());
    }

    // ── getEventHistory(ResourceEvent, Resource, UUID, EventHistoryRequestDto) ──

    @Test
    void testGetEventHistoryThrowsWhenOnlyResourceProvided() {
        EventHistoryRequestDto request = eventHistoryRequest();
        Assertions.assertThrows(ValidationException.class,
                () -> eventService.getEventHistory(
                        ResourceEvent.CERTIFICATE_DISCOVERED, Resource.CERTIFICATE, null, request),
                "Should throw when UUID is null but resource is set");
    }

    @Test
    void testGetEventHistoryThrowsWhenOnlyUuidProvided() {
        EventHistoryRequestDto request = eventHistoryRequest();
        UUID uuid = UUID.randomUUID();
        Assertions.assertThrows(ValidationException.class,
                () -> eventService.getEventHistory(
                        ResourceEvent.CERTIFICATE_DISCOVERED, null, uuid, request),
                "Should throw when resource is null but UUID is set");
    }

    @Test
    void testGetEventHistoryEmpty() throws NotFoundException {
        // fresh certificate with no event history
        UUID otherCertificateUuid = createCertificate();

        PaginationResponseDto<EventHistoryDto> response = eventService.getEventHistory(
                ResourceEvent.CERTIFICATE_DISCOVERED, Resource.CERTIFICATE, otherCertificateUuid, eventHistoryRequest());

        Assertions.assertEquals(0, response.getTotalItems());
        Assertions.assertTrue(response.getItems().isEmpty());
    }

    @Test
    void testGetEventHistoryReturnsCorrectEventData() throws NotFoundException {
        saveTriggerHistory(triggerWithNotificationUuid, UUID.randomUUID(), savedEventHistory, true, true);

        PaginationResponseDto<EventHistoryDto> response = eventService.getEventHistory(
                ResourceEvent.CERTIFICATE_DISCOVERED, Resource.CERTIFICATE, certificateUuid, eventHistoryRequest());

        Assertions.assertEquals(1, response.getTotalItems());
        EventHistoryDto dto = response.getItems().getFirst();
        Assertions.assertEquals(EventStatus.FINISHED, dto.getStatus());
        Assertions.assertNotNull(dto.getStartedAt());
        Assertions.assertNotNull(dto.getFinishedAt());
    }

    @Test
    void testGetEventHistoryObjectCounts() throws NotFoundException {
        // cert1: conditions matched by regular trigger
        saveTriggerHistory(triggerWithNotificationUuid, UUID.randomUUID(), savedEventHistory, true, true);
        // cert2: conditions not matched
        saveTriggerHistory(triggerWithNotificationUuid, UUID.randomUUID(), savedEventHistory, false, false);
        // cert3: matched by ignore trigger
        saveTriggerHistory(ignoreTriggerUuid, UUID.randomUUID(), savedEventHistory, true, false);

        PaginationResponseDto<EventHistoryDto> response = eventService.getEventHistory(
                ResourceEvent.CERTIFICATE_DISCOVERED, Resource.CERTIFICATE, certificateUuid, eventHistoryRequest());

        EventHistoryDto dto = response.getItems().getFirst();
        Assertions.assertEquals(3, dto.getObjectsEvaluated());
        Assertions.assertEquals(2, dto.getObjectsMatched()); // cert1 + cert3 (both conditionsMatched=true)
        Assertions.assertEquals(1, dto.getObjectsIgnored()); // cert3 only (ignore trigger)
    }

    @Test
    void testGetEventHistoryNestedObjectHistories() throws NotFoundException {
        saveTriggerHistory(triggerWithNotificationUuid, UUID.randomUUID(), savedEventHistory, true, true);
        saveTriggerHistory(triggerWithNotificationUuid, UUID.randomUUID(), savedEventHistory, false, false);

        PaginationResponseDto<EventHistoryDto> response = eventService.getEventHistory(
                ResourceEvent.CERTIFICATE_DISCOVERED, Resource.CERTIFICATE, certificateUuid, eventHistoryRequest());

        PaginationResponseDto<TriggerHistoryObjectSummaryDto> objectHistories =
                response.getItems().getFirst().getObjectHistories();
        Assertions.assertEquals(2, objectHistories.getTotalItems());
        Assertions.assertEquals(2, objectHistories.getItems().size());
    }

    @Test
    void testGetEventHistoryFiltersByEvent() throws NotFoundException {
        // second event history for a DIFFERENT event on the same certificate — should not appear
        EventHistory otherEventHistory = new EventHistory();
        otherEventHistory.setUuid(UUID.randomUUID());
        otherEventHistory.setEvent(ResourceEvent.CERTIFICATE_STATUS_CHANGED);
        otherEventHistory.setResource(Resource.CERTIFICATE);
        otherEventHistory.setResourceUuid(certificateUuid);
        otherEventHistory.setStartedAt(OffsetDateTime.now().minusMinutes(5));
        otherEventHistory.setStatus(EventStatus.FINISHED);
        eventHistoryRepository.save(otherEventHistory);

        PaginationResponseDto<EventHistoryDto> response = eventService.getEventHistory(
                ResourceEvent.CERTIFICATE_DISCOVERED, Resource.CERTIFICATE, certificateUuid, eventHistoryRequest());

        Assertions.assertEquals(1, response.getTotalItems());
    }

    // ── helpers ───────────────────────────────────────────────────────────────

    private UUID createCertificate() {
        CertificateContent content = new CertificateContent();
        content.setContent(UUID.randomUUID().toString());
        content = certificateContentRepository.save(content);

        Certificate certificate = new Certificate();
        certificate.setSubjectDn("CN=test");
        certificate.setIssuerDn("CN=issuer");
        certificate.setSerialNumber(UUID.randomUUID().toString());
        certificate.setState(CertificateState.ISSUED);
        certificate.setValidationStatus(CertificateValidationStatus.VALID);
        certificate.setCertificateContent(content);
        certificate.setCertificateContentId(content.getId());
        return certificateRepository.save(certificate).getUuid();
    }

    private TriggerHistory saveTriggerHistory(UUID triggerUuid, UUID objectUuid, EventHistory eventHistory,
                                               boolean conditionsMatched, boolean actionsPerformed) {
        TriggerHistory th = triggerService.createTriggerHistory(triggerUuid, null, objectUuid, null, eventHistory, Resource.CERTIFICATE);
        th.setEvent(ResourceEvent.CERTIFICATE_DISCOVERED);
        th.setConditionsMatched(conditionsMatched);
        th.setActionsPerformed(actionsPerformed);
        return triggerHistoryRepository.save(th);
    }

    private static PaginationRequestDto pagination(int itemsPerPage, int pageNumber) {
        PaginationRequestDto p = new PaginationRequestDto();
        p.setItemsPerPage(itemsPerPage);
        p.setPageNumber(pageNumber);
        return p;
    }

    private static EventHistoryRequestDto eventHistoryRequest() {
        EventHistoryRequestDto r = new EventHistoryRequestDto();
        r.getPagination().setItemsPerPage(10);
        r.getPagination().setPageNumber(1);
        r.getObjectsPagination().setItemsPerPage(10);
        r.getObjectsPagination().setPageNumber(1);
        return r;
    }
}
