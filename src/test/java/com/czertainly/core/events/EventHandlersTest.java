package com.czertainly.core.events;

import com.czertainly.api.exception.AlreadyExistException;
import com.czertainly.api.exception.AttributeException;
import com.czertainly.api.exception.EventException;
import com.czertainly.api.exception.NotFoundException;
import com.czertainly.api.model.client.approval.ApprovalStatusEnum;
import com.czertainly.api.model.client.approvalprofile.ApprovalProfileRequestDto;
import com.czertainly.api.model.client.approvalprofile.ApprovalStepDto;
import com.czertainly.api.model.client.approvalprofile.ApprovalStepRequestDto;
import com.czertainly.api.model.client.attribute.RequestAttributeV3;
import com.czertainly.api.model.client.attribute.ResponseAttribute;
import com.czertainly.api.model.client.certificate.UploadCertificateRequestDto;
import com.czertainly.api.model.client.connector.v2.ConnectorVersion;
import com.czertainly.api.model.client.notification.NotificationProfileDetailDto;
import com.czertainly.api.model.client.notification.NotificationProfileRequestDto;
import com.czertainly.api.model.common.NameAndUuidDto;
import com.czertainly.api.model.common.attribute.common.AttributeType;
import com.czertainly.api.model.common.attribute.common.content.AttributeContentType;
import com.czertainly.api.model.common.attribute.common.properties.CustomAttributeProperties;
import com.czertainly.api.model.common.attribute.v3.CustomAttributeV3;
import com.czertainly.api.model.common.attribute.v3.content.StringAttributeContentV3;
import com.czertainly.api.model.common.events.data.EventData;
import com.czertainly.api.model.common.events.data.ScheduledJobFinishedEventData;
import com.czertainly.api.model.core.auth.Resource;
import com.czertainly.api.model.core.certificate.*;
import com.czertainly.api.model.core.connector.ConnectorStatus;
import com.czertainly.api.model.core.discovery.DiscoveryStatus;
import com.czertainly.api.model.core.notification.RecipientType;
import com.czertainly.api.model.core.other.ResourceEvent;
import com.czertainly.api.model.core.search.FilterConditionOperator;
import com.czertainly.api.model.core.search.FilterFieldSource;
import com.czertainly.api.model.core.workflows.*;
import com.czertainly.api.model.scheduler.SchedulerJobExecutionStatus;
import com.czertainly.core.attribute.engine.AttributeEngine;
import com.czertainly.core.dao.entity.*;
import com.czertainly.core.dao.entity.notifications.NotificationInstanceReference;
import com.czertainly.core.dao.entity.notifications.PendingNotification;
import com.czertainly.core.dao.entity.workflows.Trigger;
import com.czertainly.core.dao.entity.workflows.TriggerAssociation;
import com.czertainly.core.dao.entity.workflows.TriggerHistory;
import com.czertainly.core.dao.repository.*;
import com.czertainly.core.dao.repository.notifications.NotificationInstanceReferenceRepository;
import com.czertainly.core.dao.repository.notifications.PendingNotificationRepository;
import com.czertainly.core.dao.entity.workflows.EventHistory;
import com.czertainly.core.dao.repository.workflows.EventHistoryRepository;
import com.czertainly.core.dao.repository.workflows.TriggerAssociationRepository;
import com.czertainly.core.dao.repository.workflows.TriggerHistoryRepository;
import com.czertainly.core.dao.repository.workflows.TriggerRepository;
import com.czertainly.core.enums.FilterField;
import com.czertainly.core.events.data.DiscoveryResult;
import com.czertainly.core.events.data.EventDataBuilder;
import com.czertainly.core.events.handlers.*;
import com.czertainly.core.helpers.CertificateGeneratorHelper;
import com.czertainly.core.messaging.jms.listeners.NotificationListener;
import com.czertainly.core.messaging.model.CertificateUploadEventMessageData;
import com.czertainly.core.messaging.model.NotificationMessage;
import com.czertainly.core.messaging.model.NotificationRecipient;
import com.czertainly.core.model.ScheduledTaskResult;
import com.czertainly.core.model.auth.ResourceAction;
import com.czertainly.core.service.*;
import com.czertainly.core.tasks.DiscoveryCertificateTask;
import com.czertainly.core.util.AuthHelper;
import com.czertainly.core.util.BaseSpringBootTest;
import com.czertainly.core.util.CertificateUtil;
import com.github.tomakehurst.wiremock.WireMockServer;
import com.github.tomakehurst.wiremock.client.WireMock;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;

import java.security.cert.X509Certificate;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.*;

class EventHandlersTest extends BaseSpringBootTest {

    public static final String CERTIFICATE_CUSTOM_ATTRIBUTE_UUID = UUID.randomUUID().toString();
    public static final String CERTIFICATE_CUSTOM_ATTRIBUTE_NAME = "category";
    @Autowired
    private TriggerRepository triggerRepository;

    @DynamicPropertySource
    static void authServiceProperties(DynamicPropertyRegistry registry) {
        registry.add("auth-service.base-url", () -> "http://localhost:10001");
    }

    @Autowired
    private CertificateService certificateService;
    @Autowired
    private CertificateEventHistoryService certificateEventHistoryService;
    @Autowired
    private RaProfileRepository raProfileRepository;
    @Autowired
    private CertificateRepository certificateRepository;
    @Autowired
    private CertificateContentRepository certificateContentRepository;
    @Autowired
    private CertificateStatusChangedEventHandler certificateStatusChangedEventHandler;
    @Autowired
    private CertificateActionPerformedEventHandler certificateActionPerformedEventHandler;
    @Autowired
    private CertificateUploadedEventHandler certificateUploadedEventHandler;

    @Autowired
    private GroupRepository groupRepository;
    @Autowired
    private ResourceObjectAssociationService associationService;

    @Autowired
    private ApprovalRepository approvalRepository;
    @Autowired
    private ApprovalProfileService approvalProfileService;
    @Autowired
    private ApprovalClosedEventHandler approvalClosedEventHandler;
    @Autowired
    private ApprovalRequestedEventHandler approvalRequestedEventHandler;

    @Autowired
    private DiscoveryRepository discoveryRepository;
    @Autowired
    private DiscoveryFinishedEventHandler discoveryFinishedEventHandler;

    @Autowired
    private AttributeEngine attributeEngine;
    @Autowired
    private RuleService ruleService;
    @Autowired
    private ActionService actionService;
    @Autowired
    private TriggerService triggerService;
    @Autowired
    private TriggerAssociationRepository triggerAssociationRepository;
    @Autowired
    private EventHistoryRepository eventHistoryRepository;
    @Autowired
    private TriggerHistoryRepository triggerHistoryRepository;

    @Autowired
    private ScheduledJobsRepository scheduledJobsRepository;
    @Autowired
    private ScheduledJobFinishedEventHandler scheduledJobFinishedEventHandler;

    @Autowired
    private ConnectorRepository connectorRepository;
    @Autowired
    private NotificationListener notificationListener;
    @Autowired
    private NotificationProfileExternalService notificationProfileService;
    @Autowired
    private PendingNotificationRepository pendingNotificationRepository;
    @Autowired
    private NotificationInstanceReferenceRepository notificationInstanceReferenceRepository;

    private WireMockServer mockServer;

    @Test
    void testCertificateStatusChangedAndApprovalEvents() throws EventException, NotFoundException, AlreadyExistException, AttributeException {
        Group group = new Group();
        group.setName("TestGroup");
        group.setEmail("grouptest@example.com");
        group = groupRepository.save(group);

        RaProfile raProfile = new RaProfile();
        raProfile.setName("Test RA profile");
        raProfile = raProfileRepository.save(raProfile);

        CertificateContent certificateContent = new CertificateContent();
        certificateContent.setContent("123456");
        certificateContent = certificateContentRepository.save(certificateContent);

        final Certificate certificate = new Certificate();
        certificate.setSubjectDn("testCertificate");
        certificate.setIssuerDn("testCercertificatetificate");
        certificate.setSerialNumber("123456789");
        certificate.setRaProfileUuid(raProfile.getUuid());
        certificate.setNotBefore(Date.from(Instant.now().minus(100, ChronoUnit.DAYS)));
        certificate.setNotAfter(Date.from(Instant.now().plus(100, ChronoUnit.DAYS)));
        certificate.setCertificateType(CertificateType.X509);
        certificate.setState(CertificateState.ISSUED);
        certificate.setValidationStatus(CertificateValidationStatus.INACTIVE);
        certificate.setCertificateContent(certificateContent);
        certificate.setCertificateContentId(certificateContent.getId());
        certificateRepository.save(certificate);

        associationService.setGroups(Resource.CERTIFICATE, certificate.getUuid(), Set.of(group.getUuid()));

        createCertificateTriggerAssociation(ResourceEvent.CERTIFICATE_STATUS_CHANGED, Resource.RA_PROFILE, raProfile.getUuid(), false);

        certificateService.validate(certificate);
        certificateStatusChangedEventHandler.handleEvent(CertificateStatusChangedEventHandler.constructEventMessage(certificate.getUuid(), CertificateValidationStatus.INACTIVE, certificate.getValidationStatus()));
        List<CertificateEventHistoryDto> historyList = certificateEventHistoryService.getCertificateEventHistory(certificate.getUuid());
        Assertions.assertEquals(1, historyList.size());
        Assertions.assertEquals(CertificateEvent.UPDATE_VALIDATION_STATUS, historyList.getFirst().getEvent());

        List<EventHistory> eventHistories = eventHistoryRepository.findAll();
        Assertions.assertEquals(1, eventHistories.size()); // one trigger associated with RA profile fired

        ApprovalProfileRequestDto approvalProfileRequestDto = new ApprovalProfileRequestDto();
        approvalProfileRequestDto.setName("TestApprovalProfile");
        approvalProfileRequestDto.setExpiry(24);
        approvalProfileRequestDto.setEnabled(true);

        ApprovalStepRequestDto approvalStepRequestDto = new ApprovalStepRequestDto();
        approvalStepRequestDto.setRoleUuid(UUID.randomUUID());
        approvalStepRequestDto.setRequiredApprovals(1);
        approvalStepRequestDto.setOrder(1);
        approvalProfileRequestDto.getApprovalSteps().add(approvalStepRequestDto);
        ApprovalProfile approvalProfile = approvalProfileService.createApprovalProfile(approvalProfileRequestDto);

        Approval approval = new Approval();
        approval.setApprovalProfileVersionUuid(approvalProfile.getTheLatestApprovalProfileVersion().getUuid());
        approval.setStatus(ApprovalStatusEnum.PENDING);
        approval.setAction(ResourceAction.REVOKE);
        approval.setResource(Resource.CERTIFICATE);
        approval.setObjectUuid(certificate.getUuid());
        approval.setCreatorUuid(UUID.randomUUID());
        approval.setCreatedAt(new Date());
        approval.setExpiryAt(Date.from(Instant.now().plus(7, ChronoUnit.DAYS)));
        approval = approvalRepository.save(approval);

        ApprovalStepDto approvalStepDto = approvalProfile.getTheLatestApprovalProfileVersion().getApprovalSteps().getFirst().mapToDto();
        approvalRequestedEventHandler.handleEvent(ApprovalRequestedEventHandler.constructEventMessage(approval.getUuid(), approvalStepDto));
        historyList = certificateEventHistoryService.getCertificateEventHistory(certificate.getUuid());
        Assertions.assertEquals(2, historyList.size());
        Assertions.assertEquals(CertificateEvent.APPROVAL_REQUEST, historyList.getFirst().getEvent());

        Assertions.assertDoesNotThrow(() -> certificateActionPerformedEventHandler.handleEvent(CertificateActionPerformedEventHandler.constructEventMessage(certificate.getUuid(), ResourceAction.REVOKE)));

        approvalClosedEventHandler.handleEvent(ApprovalClosedEventHandler.constructEventMessage(approval.getUuid()));
        historyList = certificateEventHistoryService.getCertificateEventHistory(certificate.getUuid());
        Assertions.assertEquals(3, historyList.size());
        Assertions.assertEquals(CertificateEvent.APPROVAL_CLOSE, historyList.getFirst().getEvent());

        mockServer.stop();
    }

    private void createCertificateTriggerAssociation(ResourceEvent event, Resource eventResource, UUID eventObjectUuid, boolean ignoreTrigger) throws AttributeException, AlreadyExistException, NotFoundException {
        // register custom attribute for SET_FIELD execution
        CustomAttributeV3 certAttr = new CustomAttributeV3();
        certAttr.setUuid(CERTIFICATE_CUSTOM_ATTRIBUTE_UUID);
        certAttr.setName(CERTIFICATE_CUSTOM_ATTRIBUTE_NAME);
        certAttr.setType(AttributeType.CUSTOM);
        certAttr.setContentType(AttributeContentType.STRING);
        CustomAttributeProperties customProps = new CustomAttributeProperties();
        customProps.setLabel("Certificate Category");
        certAttr.setProperties(customProps);
        attributeEngine.updateCustomAttributeDefinition(certAttr, List.of(Resource.CERTIFICATE));

        // create condition: certificate state is ISSUED
        ConditionItemRequestDto conditionItemRequest = new ConditionItemRequestDto();
        conditionItemRequest.setFieldSource(FilterFieldSource.PROPERTY);
        conditionItemRequest.setFieldIdentifier(FilterField.CERTIFICATE_STATE.name());
        conditionItemRequest.setOperator(FilterConditionOperator.EQUALS);
        conditionItemRequest.setValue(List.of(CertificateState.ISSUED.getCode()));

        ConditionRequestDto conditionRequest = new ConditionRequestDto();
        conditionRequest.setName("IssuedCertificateCondition");
        conditionRequest.setResource(Resource.CERTIFICATE);
        conditionRequest.setType(ConditionType.CHECK_FIELD);
        conditionRequest.setItems(List.of(conditionItemRequest));
        ConditionDto condition = ruleService.createCondition(conditionRequest);

        // create rule
        RuleRequestDto ruleRequest = new RuleRequestDto();
        ruleRequest.setName("IssuedCertificateRule");
        ruleRequest.setResource(Resource.CERTIFICATE);
        ruleRequest.setConditionsUuids(List.of(condition.getUuid()));
        RuleDetailDto rule = ruleService.createRule(ruleRequest);

        List<String> actionUuids = new ArrayList<>();
        if (!ignoreTrigger) {
            // create execution
            ExecutionItemRequestDto executionItemRequest = new ExecutionItemRequestDto();
            executionItemRequest.setFieldSource(FilterFieldSource.CUSTOM);
            executionItemRequest.setFieldIdentifier("%s|%s".formatted(certAttr.getName(), certAttr.getContentType().name()));
            executionItemRequest.setData("important");

            ExecutionRequestDto executionRequest = new ExecutionRequestDto();
            executionRequest.setName("CategorizeIssuedCertExecution");
            executionRequest.setResource(Resource.CERTIFICATE);
            executionRequest.setType(ExecutionType.SET_FIELD);
            executionRequest.setItems(List.of(executionItemRequest));
            ExecutionDto execution = actionService.createExecution(executionRequest);

            // create action
            ActionRequestDto actionRequest = new ActionRequestDto();
            actionRequest.setName("CategorizeIssuedCertAction");
            actionRequest.setResource(Resource.CERTIFICATE);
            actionRequest.setExecutionsUuids(List.of(execution.getUuid()));
            ActionDetailDto action = actionService.createAction(actionRequest);
            actionUuids.add(action.getUuid());
        }

        // create trigger for CERTIFICATE_STATUS_CHANGED
        TriggerRequestDto triggerRequest = new TriggerRequestDto();
        triggerRequest.setName("CertificateStatusChangedTrigger");
        triggerRequest.setType(TriggerType.EVENT);
        triggerRequest.setEvent(event);
        triggerRequest.setResource(Resource.CERTIFICATE);
        triggerRequest.setRulesUuids(List.of(rule.getUuid()));
        triggerRequest.setActionsUuids(actionUuids);
        triggerRequest.setIgnoreTrigger(ignoreTrigger);
        TriggerDetailDto trigger = triggerService.createTrigger(triggerRequest);

        // set up WireMock as auth service (required by createTriggerAssociations)
        mockServer = new WireMockServer(10001);
        mockServer.start();
        WireMock.configureFor("localhost", mockServer.port());

        NameAndUuidDto userInfo = AuthHelper.getUserIdentification();
        mockAuthResponse(userInfo);

        // associate trigger with RA profile for CERTIFICATE_STATUS_CHANGED
        triggerService.createTriggerAssociations(event, eventResource, eventObjectUuid, List.of(UUID.fromString(trigger.getUuid())), true);
    }

    @Test
    void testProcessTriggersExceptionSetsEventHistoryToFailed() throws EventException {
        DiscoveryHistory discovery = new DiscoveryHistory();
        discovery.setName("TestDiscovery");
        discovery.setKind("IP");
        discovery.setStatus(DiscoveryStatus.IN_PROGRESS);
        discovery.setConnectorUuid(UUID.randomUUID());
        discovery.setConnectorStatus(DiscoveryStatus.COMPLETED);
        discovery = discoveryRepository.save(discovery);

        // Create trigger entity directly, bypassing service validation, since evaluateTrigger is never reached
        Trigger trigger = new Trigger();
        trigger.setName("TestFailureTrigger");
        trigger.setType(TriggerType.EVENT);
        trigger.setResource(Resource.DISCOVERY);
        trigger.setEvent(ResourceEvent.DISCOVERY_FINISHED);
        trigger.setIgnoreTrigger(false);
        trigger = triggerRepository.save(trigger);

        // A fresh random UUID guarantees a cache miss in the auth cache — handleUser will call the auth service
        UUID randomUserUuid = UUID.randomUUID();
        TriggerAssociation association = new TriggerAssociation();
        association.setTriggerUuid(trigger.getUuid());
        association.setEvent(ResourceEvent.DISCOVERY_FINISHED);
        association.setTriggeredBy(randomUserUuid);
        triggerAssociationRepository.save(association);

        // No auth service is running on port 10001, so authenticateAsUser throws CzertainlyAuthenticationException,
        // which escapes handleUser (catches only ValidationException) and is caught by the outer catch in
        // processTriggers (EventHandler line 208), which sets EventStatus.FAILED on the event history.
        discoveryFinishedEventHandler.handleEvent(
                DiscoveryFinishedEventHandler.constructEventMessage(discovery.getUuid(), null, null, new DiscoveryResult(DiscoveryStatus.COMPLETED, "Test")));

        List<EventHistory> eventHistories = eventHistoryRepository.findAll();
        Assertions.assertEquals(1, eventHistories.size());
        Assertions.assertEquals(EventStatus.FAILED, eventHistories.getFirst().getStatus());
        Assertions.assertNotNull(eventHistories.getFirst().getFinishedAt());
    }

    @Test
    void testDiscoveryFinishedEvent() throws EventException, AttributeException, AlreadyExistException, NotFoundException {
        DiscoveryHistory discovery = new DiscoveryHistory();
        discovery.setName("TestDiscovery");
        discovery.setKind("IP");
        discovery.setStatus(DiscoveryStatus.IN_PROGRESS);
        discovery.setConnectorUuid(UUID.randomUUID());
        discovery.setConnectorStatus(DiscoveryStatus.COMPLETED);
        discovery = discoveryRepository.save(discovery);

        // register custom attribute
        CustomAttributeV3 certificateDomainAttr = new CustomAttributeV3();
        certificateDomainAttr.setUuid(CERTIFICATE_CUSTOM_ATTRIBUTE_UUID);
        certificateDomainAttr.setName("domain");
        certificateDomainAttr.setType(AttributeType.CUSTOM);
        certificateDomainAttr.setContentType(AttributeContentType.STRING);
        CustomAttributeProperties customProps = new CustomAttributeProperties();
        customProps.setLabel("Domain of discovery");
        certificateDomainAttr.setProperties(customProps);
        attributeEngine.updateCustomAttributeDefinition(certificateDomainAttr, List.of(Resource.DISCOVERY));

        // create conditions
        ConditionItemRequestDto conditionItemRequest = new ConditionItemRequestDto();
        conditionItemRequest.setFieldSource(FilterFieldSource.PROPERTY);
        conditionItemRequest.setFieldIdentifier(FilterField.DISCOVERY_KIND.name());
        conditionItemRequest.setOperator(FilterConditionOperator.EQUALS);
        conditionItemRequest.setValue("IP");

        ConditionRequestDto conditionRequest = new ConditionRequestDto();
        conditionRequest.setName("IPKindDiscoveryCondition");
        conditionRequest.setResource(Resource.DISCOVERY);
        conditionRequest.setType(ConditionType.CHECK_FIELD);
        conditionRequest.setItems(List.of(conditionItemRequest));
        ConditionDto condition = ruleService.createCondition(conditionRequest);

        // create ignore condition
        conditionItemRequest.setValue("RandomName");
        conditionItemRequest.setFieldIdentifier(FilterField.DISCOVERY_NAME.name());
        conditionRequest.setName("DiscoveryNameEqualsCondition");
        ConditionDto conditionIgnore = ruleService.createCondition(conditionRequest);

        // create rule
        RuleRequestDto ruleRequest = new RuleRequestDto();
        ruleRequest.setName("IPKindDiscoveryRule");
        ruleRequest.setResource(Resource.DISCOVERY);
        ruleRequest.setConditionsUuids(List.of(condition.getUuid()));
        RuleDetailDto rule = ruleService.createRule(ruleRequest);

        // create ignore rule
        ruleRequest.setName("DiscoveryNameEqualsRule");
        ruleRequest.setConditionsUuids(List.of(conditionIgnore.getUuid()));
        RuleDetailDto ruleIgnore = ruleService.createRule(ruleRequest);

        // create execution
        ExecutionItemRequestDto executionItemRequest = new ExecutionItemRequestDto();
        executionItemRequest.setFieldSource(FilterFieldSource.CUSTOM);
        executionItemRequest.setFieldIdentifier("%s|%s".formatted(certificateDomainAttr.getName(), certificateDomainAttr.getContentType().name()));
        executionItemRequest.setData("CZ");

        ExecutionRequestDto executionRequest = new ExecutionRequestDto();
        executionRequest.setName("CategorizeCertificatesExecution");
        executionRequest.setResource(Resource.DISCOVERY);
        executionRequest.setType(ExecutionType.SET_FIELD);
        executionRequest.setItems(List.of(executionItemRequest));
        ExecutionDto execution = actionService.createExecution(executionRequest);

        // create action
        ActionRequestDto actionRequest = new ActionRequestDto();
        actionRequest.setName("CategorizeCertificatesAction");
        actionRequest.setResource(Resource.DISCOVERY);
        actionRequest.setExecutionsUuids(List.of(execution.getUuid()));
        ActionDetailDto action = actionService.createAction(actionRequest);

        // create trigger
        TriggerRequestDto triggerRequest = new TriggerRequestDto();
        triggerRequest.setName("DiscoveryCertificatesCategorization");
        triggerRequest.setType(TriggerType.EVENT);
        triggerRequest.setEvent(ResourceEvent.DISCOVERY_FINISHED);
        triggerRequest.setResource(Resource.DISCOVERY);
        triggerRequest.setRulesUuids(List.of(rule.getUuid()));
        triggerRequest.setActionsUuids(List.of(action.getUuid()));
        TriggerDetailDto trigger = triggerService.createTrigger(triggerRequest);

        // create ignore trigger
        triggerRequest.setName("DiscoveryFinishedCategorizationIgnore");
        triggerRequest.setRulesUuids(List.of(ruleIgnore.getUuid()));
        triggerRequest.setIgnoreTrigger(true);
        triggerRequest.setActionsUuids(List.of());
        TriggerDetailDto triggerIgnore = triggerService.createTrigger(triggerRequest);

        NameAndUuidDto userInfo = AuthHelper.getUserIdentification();
        UUID userUuid = UUID.fromString(userInfo.getUuid());

        mockServer = new WireMockServer(10001);
        mockServer.start();
        WireMock.configureFor("localhost", mockServer.port());

        mockAuthResponse(userInfo);

        triggerService.createTriggerAssociations(ResourceEvent.DISCOVERY_FINISHED, null, null, List.of(UUID.fromString(triggerIgnore.getUuid()), UUID.fromString(trigger.getUuid())), true);

        discoveryFinishedEventHandler.handleEvent(DiscoveryFinishedEventHandler.constructEventMessage(discovery.getUuid(), userUuid, null, new DiscoveryResult(DiscoveryStatus.COMPLETED, "Test")));
        discovery = discoveryRepository.findByUuid(discovery.getUuid()).orElseThrow();
        Assertions.assertEquals(DiscoveryStatus.IN_PROGRESS, discovery.getStatus());

        discoveryFinishedEventHandler.handleEvent(DiscoveryFinishedEventHandler.constructEventMessage(discovery.getUuid(), null, null, new DiscoveryResult(DiscoveryStatus.PROCESSING, "Test finalize")));
        discovery = discoveryRepository.findByUuid(discovery.getUuid()).orElseThrow();
        Assertions.assertEquals(DiscoveryStatus.COMPLETED, discovery.getStatus());

        // each handleEvent call processes one platform-level trigger group → one EventHistory per call
        List<EventHistory> eventHistories = eventHistoryRepository.findAll();
        Assertions.assertEquals(2, eventHistories.size(), "Expected one EventHistory record per handleEvent call");
        eventHistories.forEach(eh -> {
            Assertions.assertEquals(ResourceEvent.DISCOVERY_FINISHED, eh.getEvent());
            Assertions.assertEquals(EventStatus.FINISHED, eh.getStatus());
            Assertions.assertNotNull(eh.getStartedAt());
            Assertions.assertNotNull(eh.getFinishedAt());
        });

        mockServer.stop();
    }

    private void mockAuthResponse(NameAndUuidDto userInfo) {
        mockServer.stubFor(WireMock.get(WireMock.urlPathMatching("/auth/users/[^/]+")).willReturn(
                WireMock.okJson("""
                {
                    "uuid": "%s",
                    "username": "%s",
                    "email": "testuser1@example.com",
                    "groups": [],
                    "roles": []
                }
                """.formatted(userInfo.getUuid(), userInfo.getName()))
        ));

        mockServer.stubFor(WireMock.post(WireMock.urlPathMatching("/auth")).willReturn(
                WireMock.okJson("""
                {
                                  "authenticated": true,
                                  "data": {
                                    "user": {
                                      "uuid": "%s",
                                      "username": "%s"
                                    },
                                    "roles": [
                                      {
                                        "name": "superadmin"
                                      }
                                    ],
                                    "permissions": {
                                      "allowAllResources": true,
                                      "resources": []
                                    }
                                  }
                                }
                """.formatted(userInfo.getUuid(), userInfo.getName()))
        ));
    }

    @Test
    void testScheduledJobFinishedEvent() {
        final ScheduledJob scheduledJob = new ScheduledJob();
        scheduledJob.setJobName("TestJob");
        scheduledJob.setCronExpression("0 0/3 * * * ? *");
        scheduledJob.setEnabled(true);
        scheduledJob.setSystem(false);
        scheduledJob.setOneTime(false);
        scheduledJob.setUserUuid(UUID.randomUUID());
        scheduledJob.setJobClassName(DiscoveryCertificateTask.class.getName());
        scheduledJobsRepository.save(scheduledJob);

        Assertions.assertDoesNotThrow(() -> scheduledJobFinishedEventHandler.handleEvent(ScheduledJobFinishedEventHandler.constructEventMessage(scheduledJob.getUuid(), new ScheduledTaskResult(SchedulerJobExecutionStatus.SUCCESS, "Test"))));

        ScheduledJobFinishedEventData eventData = new ScheduledJobFinishedEventData();
        eventData.setJobName(scheduledJob.getJobName());
        eventData.setJobType(scheduledJob.getJobType());
        eventData.setStatus(SchedulerJobExecutionStatus.SUCCESS.getLabel());
        NotificationMessage notificationMessage = new NotificationMessage(ResourceEvent.SCHEDULED_JOB_FINISHED, Resource.SCHEDULED_JOB, scheduledJob.getUuid(), null, NotificationRecipient.buildUserNotificationRecipient(UUID.randomUUID()), eventData);
        Assertions.assertDoesNotThrow(() -> notificationListener.processMessage(notificationMessage));
    }

    @Test
    void testCertificateUploadedEventCertificateIgnored() throws Exception {
        X509Certificate certificate = CertificateGeneratorHelper.generateCACertificate(null, "CN=test");
        String fingerprint = CertificateUtil.getThumbprint(certificate);
        final CertificateUploadEventMessageData eventMessageData = CertificateUploadEventMessageData.builder()
                .certificateContent(Base64.getEncoder().encodeToString(certificate.getEncoded()))
                .build();

        createCertificateTriggerAssociation(ResourceEvent.CERTIFICATE_UPLOADED, null, null, true);
        Assertions.assertDoesNotThrow(() -> certificateUploadedEventHandler.handleEvent(CertificateUploadedEventHandler.constructEventMessage(eventMessageData)));
        Assertions.assertFalse(certificateRepository.findByFingerprint(fingerprint).isPresent());

        List<TriggerHistory> histories = triggerHistoryRepository.findAll();
        Assertions.assertEquals(1, histories.size());
        TriggerHistory th = histories.getFirst();
        Assertions.assertTrue(th.isConditionsMatched());
        Assertions.assertTrue(th.isActionsPerformed());

        Assertions.assertNotNull(th.getMessage());
        Assertions.assertTrue(th.getMessage().contains(fingerprint), "ignore TriggerHistory.message includes the fingerprint");
        mockServer.stop();
    }

    @Test
    void testCertificateUploadedEventCertificateMalformedContent() {
        final CertificateUploadEventMessageData eventMessageData = CertificateUploadEventMessageData.builder()
                .certificateContent("invalid")
                .build();

        Assertions.assertDoesNotThrow(() -> certificateUploadedEventHandler.handleEvent(CertificateUploadedEventHandler.constructEventMessage(eventMessageData)));
        EventHistory eventHistory = eventHistoryRepository.findAll().stream().findFirst().orElseThrow();
        Assertions.assertEquals(EventStatus.FAILED, eventHistory.getStatus());
    }

    @Test
    void testCertificateUploadedEventCertificateDuplicateFingerprint() throws Exception {
        X509Certificate certificate = CertificateGeneratorHelper.generateCACertificate(null, "CN=test");
        final CertificateUploadEventMessageData eventMessageData = CertificateUploadEventMessageData.builder()
                .certificateContent(Base64.getEncoder().encodeToString(certificate.getEncoded()))
                .build();

        UploadCertificateRequestDto uploadCertificateRequestDto = new UploadCertificateRequestDto();
        uploadCertificateRequestDto.setCertificate(Base64.getEncoder().encodeToString(certificate.getEncoded()));
        certificateService.uploadSync(uploadCertificateRequestDto);

        // Test duplicate fingerprint
        Assertions.assertDoesNotThrow(() -> certificateUploadedEventHandler.handleEvent(CertificateUploadedEventHandler.constructEventMessage(eventMessageData)));
        // The first history is for the created certificate, so we need to check the second one
        EventHistory eventHistory = eventHistoryRepository.findAll().getLast();
        Assertions.assertEquals(EventStatus.FAILED, eventHistory.getStatus());
    }

    @Test
    void testCertificateUploadedEvent() throws Exception {
        X509Certificate certificate = CertificateGeneratorHelper.generateCACertificate(null, "CN=test");
        String fingerprint = CertificateUtil.getThumbprint(certificate);
        final CertificateUploadEventMessageData eventMessageData = CertificateUploadEventMessageData.builder()
                .certificateContent(Base64.getEncoder().encodeToString(certificate.getEncoded()))
                .build();

        // Test without any triggers in settings
        Assertions.assertDoesNotThrow(() -> certificateUploadedEventHandler.handleEvent(CertificateUploadedEventHandler.constructEventMessage(eventMessageData)));

        Certificate uploadedCertificate = certificateRepository.findByFingerprint(fingerprint).orElseThrow();
        Assertions.assertEquals(certificate.getSubjectX500Principal().getName(), uploadedCertificate.getSubjectDn());
        Assertions.assertNotNull(uploadedCertificate.getCertificateContent());
        Assertions.assertNotNull(uploadedCertificate.getKey());

        // Test setting actions
        certificateService.deleteCertificate(uploadedCertificate.getSecuredUuid());

        createCertificateTriggerAssociation(ResourceEvent.CERTIFICATE_UPLOADED, null, null, false);
        Assertions.assertDoesNotThrow(() -> certificateUploadedEventHandler.handleEvent(CertificateUploadedEventHandler.constructEventMessage(eventMessageData)));
        uploadedCertificate = certificateRepository.findByFingerprint(fingerprint).orElseThrow();
        CertificateDetailDto certificateDetailDto = certificateService.getCertificate(uploadedCertificate.getSecuredUuid());
        Assertions.assertFalse(certificateDetailDto.getCustomAttributes().isEmpty());

        // Test setting actions with custom attributes in the request and user UUID
        RequestAttributeV3 requestAttributeV3 = new RequestAttributeV3();
        requestAttributeV3.setUuid(UUID.fromString(CERTIFICATE_CUSTOM_ATTRIBUTE_UUID));
        requestAttributeV3.setName(CERTIFICATE_CUSTOM_ATTRIBUTE_NAME);
        requestAttributeV3.setContentType(AttributeContentType.STRING);
        requestAttributeV3.setContent(List.of(new StringAttributeContentV3("fromRequest")));
        CertificateUploadEventMessageData eventMessageData2 = CertificateUploadEventMessageData.builder()
                .certificateContent(Base64.getEncoder().encodeToString(certificate.getEncoded()))
                .customAttributes(List.of(requestAttributeV3))
                .build();

        certificateService.deleteCertificate(uploadedCertificate.getSecuredUuid());
        Assertions.assertDoesNotThrow(() -> certificateUploadedEventHandler.handleEvent(CertificateUploadedEventHandler.constructEventMessage(eventMessageData2)));
        uploadedCertificate = certificateRepository.findByFingerprint(fingerprint).orElseThrow();
        certificateDetailDto = certificateService.getCertificate(uploadedCertificate.getSecuredUuid());
        Assertions.assertFalse(certificateDetailDto.getCustomAttributes().isEmpty());
        Optional<ResponseAttribute> customAttributeDtoOptional = certificateDetailDto.getCustomAttributes().stream().filter(attr -> CERTIFICATE_CUSTOM_ATTRIBUTE_NAME.equals(attr.getName())).findFirst();
        Assertions.assertTrue(customAttributeDtoOptional.isPresent());
        Assertions.assertEquals("fromRequest", ((List<StringAttributeContentV3>) customAttributeDtoOptional.get().getContent()).getFirst().getData());
        mockServer.stop();
    }

    @Test
    void testEventDataNotifications() throws NotFoundException, AlreadyExistException {
        Group group = new Group();
        group.setName("TestGroup");
        group.setEmail("grouptest@example.com");
        group = groupRepository.save(group);

        mockServer = new WireMockServer(10001);
        mockServer.start();
        WireMock.configureFor("localhost", mockServer.port());

        UUID ownerUuid = UUID.randomUUID();
        UUID roleUuid = UUID.randomUUID();
        var notificationProfileUuids = prepareDataAndMockServer(mockServer, group, ownerUuid, roleUuid);

        // test certificate events
        CertificateContent certificateContent = new CertificateContent();
        certificateContent.setContent("123456");
        certificateContent = certificateContentRepository.save(certificateContent);

        final Certificate certificate = new Certificate();
        certificate.setSubjectDn("testCertificate");
        certificate.setIssuerDn("testCertificateIssuer");
        certificate.setSerialNumber("123456789");
        certificate.setNotBefore(Date.from(Instant.now().minus(100, ChronoUnit.DAYS)));
        certificate.setNotAfter(Date.from(Instant.now().plus(100, ChronoUnit.DAYS)));
        certificate.setCertificateType(CertificateType.X509);
        certificate.setState(CertificateState.ISSUED);
        certificate.setValidationStatus(CertificateValidationStatus.INACTIVE);
        certificate.setCertificateContent(certificateContent);
        certificate.setCertificateContentId(certificateContent.getId());
        certificateRepository.save(certificate);

        associationService.setOwner(Resource.CERTIFICATE, certificate.getUuid(), ownerUuid);
        associationService.setGroups(Resource.CERTIFICATE, certificate.getUuid(), Set.of(group.getUuid()));

        // test event data handling
        EventData eventData = EventDataBuilder.getCertificateStatusChangedEventData(certificate, new CertificateValidationStatus[]{CertificateValidationStatus.INACTIVE, CertificateValidationStatus.VALID});
        final NotificationMessage messageCertificateStatusChanged = new NotificationMessage(ResourceEvent.CERTIFICATE_STATUS_CHANGED, Resource.CERTIFICATE, certificate.getUuid(), notificationProfileUuids, null, eventData);
        Assertions.assertDoesNotThrow(() -> notificationListener.processMessage(messageCertificateStatusChanged));
        Assertions.assertDoesNotThrow(() -> notificationListener.processMessage(messageCertificateStatusChanged));
        PendingNotification pendingNotification = pendingNotificationRepository.findByNotificationProfileUuidAndResourceAndObjectUuidAndEvent(notificationProfileUuids.getLast(), Resource.CERTIFICATE, certificate.getUuid(), ResourceEvent.CERTIFICATE_STATUS_CHANGED);
        Assertions.assertNull(pendingNotification);

        eventData = EventDataBuilder.getCertificateActionPerformedEventData(certificate, ResourceAction.REVOKE);
        final NotificationMessage messageCertificateActionPerformed = new NotificationMessage(ResourceEvent.CERTIFICATE_ACTION_PERFORMED, Resource.CERTIFICATE, certificate.getUuid(), notificationProfileUuids, null, eventData);
        Assertions.assertDoesNotThrow(() -> notificationListener.processMessage(messageCertificateActionPerformed));

        DiscoveryHistory discovery = new DiscoveryHistory();
        discovery.setName("TestDiscovery");
        discovery.setStatus(DiscoveryStatus.COMPLETED);
        discovery.setConnectorStatus(DiscoveryStatus.COMPLETED);
        discovery.setConnectorUuid(UUID.randomUUID());
        discovery.setConnectorName("TestDiscoveryConnector");
        discoveryRepository.save(discovery);

        eventData = EventDataBuilder.getCertificateDiscoveredEventData(certificate, discovery, ownerUuid);
        final NotificationMessage messageCertificateDiscovered = new NotificationMessage(ResourceEvent.CERTIFICATE_DISCOVERED, Resource.CERTIFICATE, certificate.getUuid(), notificationProfileUuids, null, eventData);
        Assertions.assertDoesNotThrow(() -> notificationListener.processMessage(messageCertificateDiscovered));

        // discovery events
        eventData = EventDataBuilder.getDiscoveryFinishedEventData(discovery);
        final NotificationMessage messageDiscoveryFinished = new NotificationMessage(ResourceEvent.DISCOVERY_FINISHED, Resource.DISCOVERY, discovery.getUuid(), notificationProfileUuids, null, eventData);
        Assertions.assertDoesNotThrow(() -> notificationListener.processMessage(messageDiscoveryFinished));

        // approvals events
        ApprovalProfileRequestDto approvalProfileRequestDto = new ApprovalProfileRequestDto();
        approvalProfileRequestDto.setName("TestApprovalProfile");
        approvalProfileRequestDto.setExpiry(24);
        approvalProfileRequestDto.setEnabled(true);

        ApprovalStepRequestDto approvalStepRequestDto = new ApprovalStepRequestDto();
        approvalStepRequestDto.setGroupUuid(group.getUuid());
        approvalStepRequestDto.setRequiredApprovals(1);
        approvalStepRequestDto.setOrder(1);
        approvalProfileRequestDto.getApprovalSteps().add(approvalStepRequestDto);
        ApprovalProfile approvalProfile = approvalProfileService.createApprovalProfile(approvalProfileRequestDto);

        Approval approval = new Approval();
        approval.setApprovalProfileVersion(approvalProfile.getTheLatestApprovalProfileVersion());
        approval.setApprovalProfileVersionUuid(approvalProfile.getTheLatestApprovalProfileVersion().getUuid());
        approval.setStatus(ApprovalStatusEnum.PENDING);
        approval.setAction(ResourceAction.REVOKE);
        approval.setResource(Resource.CERTIFICATE);
        approval.setObjectUuid(certificate.getUuid());
        approval.setCreatorUuid(UUID.randomUUID());
        approval.setCreatedAt(new Date());
        approval.setExpiryAt(Date.from(Instant.now().plus(7, ChronoUnit.DAYS)));
        approval = approvalRepository.save(approval);

        ApprovalStepDto approvalStepDto = approvalProfile.getTheLatestApprovalProfileVersion().getApprovalSteps().getFirst().mapToDto();
        eventData = EventDataBuilder.getApprovalRequestedEventData(approval, approvalProfile, approvalStepDto, "TestUser1");
        final NotificationMessage messageApprovalRequested = new NotificationMessage(ResourceEvent.APPROVAL_REQUESTED, Resource.APPROVAL, approval.getUuid(), notificationProfileUuids, null, eventData);
        Assertions.assertDoesNotThrow(() -> notificationListener.processMessage(messageApprovalRequested));

        eventData = EventDataBuilder.getApprovalEventData(approval, approvalProfile, "TestUser1");
        final NotificationMessage messageApprovalClosed = new NotificationMessage(ResourceEvent.APPROVAL_CLOSED, Resource.APPROVAL, approval.getUuid(), notificationProfileUuids, null, eventData);
        Assertions.assertDoesNotThrow(() -> notificationListener.processMessage(messageApprovalClosed));

        eventData = EventDataBuilder.getCertificateExpiringEventData(certificate);
        final NotificationMessage messageCertificateExpiring = new NotificationMessage(ResourceEvent.CERTIFICATE_EXPIRING, Resource.CERTIFICATE, certificate.getUuid(), notificationProfileUuids, null, eventData);
        Assertions.assertDoesNotThrow(() -> notificationListener.processMessage(messageCertificateExpiring));
        Assertions.assertDoesNotThrow(() -> notificationListener.processMessage(messageCertificateExpiring));
        pendingNotification = pendingNotificationRepository.findByNotificationProfileUuidAndResourceAndObjectUuidAndEvent(notificationProfileUuids.getLast(), Resource.CERTIFICATE, certificate.getUuid(), ResourceEvent.CERTIFICATE_EXPIRING);
        Assertions.assertNotNull(pendingNotification);
        Assertions.assertEquals(1, pendingNotification.getRepetitions(), "Second notification should be suppressed");

        mockServer.stop();
    }

    private List<UUID> prepareDataAndMockServer(WireMockServer mockServer, Group group, UUID ownerUuid, UUID roleUuid) throws NotFoundException, AlreadyExistException {
        String ownerUserResponse = """
                {
                    "uuid": "%s",
                    "username": "TestUser1",
                    "email": "testuser1@example.com",
                    "groups": [
                        {
                            "uuid": "%s",
                            "name": "%s"
                        }
                    ],
                    "roles": []
                }
                """.formatted(ownerUuid, group.getUuid(), group.getName());

        String userListResponse = """
                [
                    %s,
                    {
                        "uuid": "%s",
                        "username": "TestUser2",
                        "email": "testuser2@example.com",
                        "groups": [
                            {
                                "uuid": "%s",
                                "name": "%s"
                            }
                        ]
                    }
                ]
                """.formatted(ownerUserResponse, UUID.randomUUID(), group.getUuid(), group.getName());

        mockServer.stubFor(WireMock.get(WireMock.urlPathMatching("/v1/notificationProvider/[^/]+/attributes/mapping")).willReturn(WireMock.okJson("[]")));
        mockServer.stubFor(WireMock.post(WireMock.urlPathMatching("/v1/notificationProvider/notifications/[^/]+/notify")).willReturn(WireMock.ok()));
        mockServer.stubFor(WireMock.get(WireMock.urlPathMatching("/auth/roles/[^/]+")).willReturn(
                WireMock.okJson("""
                        {
                            "uuid": "%s",
                            "name": "TestRole",
                            "email": "testrole@example.com",
                            "systemRole": false
                        },
                        """.formatted(roleUuid.toString()))
        ));
        mockServer.stubFor(WireMock.get(WireMock.urlPathMatching("/auth/users")).willReturn(
                WireMock.okJson("""
                        {
                            "data": %s
                        }
                        """.formatted(userListResponse))
        ));
        mockServer.stubFor(WireMock.get(WireMock.urlPathMatching("/auth/users/[^/]+")).willReturn(
                WireMock.okJson(ownerUserResponse)
        ));
        mockServer.stubFor(WireMock.get(WireMock.urlPathMatching("/auth/roles/[^/]+/users")).willReturn(
                WireMock.okJson(userListResponse)
        ));

        Connector connector = new Connector();
        connector.setName("notificationInstanceConnector");
        connector.setUrl("http://localhost:" + mockServer.port());
        connector.setVersion(ConnectorVersion.V1);
        connector.setStatus(ConnectorStatus.CONNECTED);
        connector = connectorRepository.save(connector);

        NotificationInstanceReference instance = new NotificationInstanceReference();
        instance.setName("TestNotificationInstance");
        instance.setKind("EMAIL");
        instance.setConnectorUuid(connector.getUuid());
        instance.setNotificationInstanceUuid(UUID.randomUUID());
        notificationInstanceReferenceRepository.save(instance);

        NotificationProfileRequestDto requestDto = new NotificationProfileRequestDto();
        requestDto.setName("TestProfileDefault");
        requestDto.setRecipientType(RecipientType.DEFAULT);
        requestDto.setInternalNotification(true);
        requestDto.setNotificationInstanceUuid(instance.getUuid());
        NotificationProfileDetailDto notificationProfileDetailDto = notificationProfileService.createNotificationProfile(requestDto);

        requestDto.setName("TestProfileRole");
        requestDto.setRecipientType(RecipientType.ROLE);
        requestDto.setRecipientUuids(List.of(roleUuid));
        NotificationProfileDetailDto notificationProfileDetailDto2 = notificationProfileService.createNotificationProfile(requestDto);

        requestDto.setName("TestProfileUser");
        requestDto.setRecipientType(RecipientType.USER);
        requestDto.setRecipientUuids(List.of(ownerUuid));
        NotificationProfileDetailDto notificationProfileDetailDto3 = notificationProfileService.createNotificationProfile(requestDto);

        requestDto.setName("TestProfileOwner");
        requestDto.setRecipientType(RecipientType.OWNER);
        requestDto.setRecipientUuids(null);
        NotificationProfileDetailDto notificationProfileDetailDto4 = notificationProfileService.createNotificationProfile(requestDto);

        requestDto.setName("TestProfileGroup");
        requestDto.setRepetitions(1);
        requestDto.setRecipientType(RecipientType.GROUP);
        requestDto.setRecipientUuids(List.of(group.getUuid()));
        NotificationProfileDetailDto notificationProfileDetailDto5 = notificationProfileService.createNotificationProfile(requestDto);

        return List.of(UUID.fromString(notificationProfileDetailDto.getUuid()),
                UUID.fromString(notificationProfileDetailDto2.getUuid()),
                UUID.fromString(notificationProfileDetailDto3.getUuid()),
                UUID.fromString(notificationProfileDetailDto4.getUuid()),
                UUID.fromString(notificationProfileDetailDto5.getUuid()));

    }
}
