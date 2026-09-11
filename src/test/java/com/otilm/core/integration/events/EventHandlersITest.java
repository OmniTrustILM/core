package com.otilm.core.integration.events;

import com.github.tomakehurst.wiremock.WireMockServer;
import com.github.tomakehurst.wiremock.client.WireMock;
import com.otilm.api.exception.AlreadyExistException;
import com.otilm.api.exception.AttributeException;
import com.otilm.api.exception.EventException;
import com.otilm.api.exception.NotFoundException;
import com.otilm.api.model.client.approval.ApprovalStatusEnum;
import com.otilm.api.model.client.approvalprofile.ApprovalProfileRequestDto;
import com.otilm.api.model.client.approvalprofile.ApprovalStepDto;
import com.otilm.api.model.client.approvalprofile.ApprovalStepRequestDto;
import com.otilm.api.model.client.attribute.RequestAttributeV3;
import com.otilm.api.model.client.attribute.ResponseAttribute;
import com.otilm.api.model.client.certificate.UploadCertificateRequestDto;
import com.otilm.api.model.client.connector.v2.ConnectorVersion;
import com.otilm.api.model.client.notification.NotificationProfileDetailDto;
import com.otilm.api.model.client.notification.NotificationProfileRequestDto;
import com.otilm.api.model.common.NameAndUuidDto;
import com.otilm.api.model.common.attribute.common.AttributeType;
import com.otilm.api.model.common.attribute.common.content.AttributeContentType;
import com.otilm.api.model.common.attribute.common.properties.CustomAttributeProperties;
import com.otilm.api.model.common.attribute.v3.CustomAttributeV3;
import com.otilm.api.model.common.attribute.v3.content.StringAttributeContentV3;
import com.otilm.api.model.common.events.data.EventData;
import com.otilm.api.model.common.events.data.ScheduledJobFinishedEventData;
import com.otilm.api.model.core.auth.Resource;
import com.otilm.api.model.core.certificate.CertificateDetailDto;
import com.otilm.api.model.core.certificate.CertificateEvent;
import com.otilm.api.model.core.certificate.CertificateEventHistoryDto;
import com.otilm.api.model.core.certificate.CertificateState;
import com.otilm.api.model.core.certificate.CertificateType;
import com.otilm.api.model.core.certificate.CertificateValidationStatus;
import com.otilm.api.model.core.compliance.ComplianceStatus;
import com.otilm.api.model.core.connector.ConnectorStatus;
import com.otilm.api.model.core.discovery.DiscoveryStatus;
import com.otilm.api.model.core.notification.RecipientType;
import com.otilm.api.model.core.other.ResourceEvent;
import com.otilm.api.model.core.search.FilterConditionOperator;
import com.otilm.api.model.core.search.FilterFieldSource;
import com.otilm.api.model.core.workflows.ActionDetailDto;
import com.otilm.api.model.core.workflows.ActionRequestDto;
import com.otilm.api.model.core.workflows.ConditionDto;
import com.otilm.api.model.core.workflows.ConditionItemRequestDto;
import com.otilm.api.model.core.workflows.ConditionRequestDto;
import com.otilm.api.model.core.workflows.ConditionType;
import com.otilm.api.model.core.workflows.EventStatus;
import com.otilm.api.model.core.workflows.ExecutionDto;
import com.otilm.api.model.core.workflows.ExecutionItemRequestDto;
import com.otilm.api.model.core.workflows.ExecutionRequestDto;
import com.otilm.api.model.core.workflows.ExecutionType;
import com.otilm.api.model.core.workflows.RuleDetailDto;
import com.otilm.api.model.core.workflows.RuleRequestDto;
import com.otilm.api.model.core.workflows.TriggerDetailDto;
import com.otilm.api.model.core.workflows.TriggerRequestDto;
import com.otilm.api.model.core.workflows.TriggerType;
import com.otilm.api.model.scheduler.SchedulerJobExecutionStatus;
import com.otilm.core.attribute.engine.AttributeEngine;
import com.otilm.core.dao.entity.Approval;
import com.otilm.core.dao.entity.ApprovalProfile;
import com.otilm.core.dao.entity.Certificate;
import com.otilm.core.dao.entity.CertificateContent;
import com.otilm.core.dao.entity.Connector;
import com.otilm.core.dao.entity.Discovery;
import com.otilm.core.dao.entity.DiscoveryCertificate;
import com.otilm.core.dao.entity.Group;
import com.otilm.core.dao.entity.GroupAssociation;
import com.otilm.core.dao.entity.RaProfile;
import com.otilm.core.dao.entity.ScheduledJob;
import com.otilm.core.dao.entity.notifications.NotificationInstanceReference;
import com.otilm.core.dao.entity.notifications.PendingNotification;
import com.otilm.core.dao.entity.workflows.EventHistory;
import com.otilm.core.dao.entity.workflows.Trigger;
import com.otilm.core.dao.entity.workflows.TriggerAssociation;
import com.otilm.core.dao.entity.workflows.TriggerHistory;
import com.otilm.core.dao.repository.ApprovalRepository;
import com.otilm.core.dao.repository.CertificateContentRepository;
import com.otilm.core.dao.repository.CertificateRepository;
import com.otilm.core.dao.repository.ConnectorRepository;
import com.otilm.core.dao.repository.DiscoveryCertificateRepository;
import com.otilm.core.dao.repository.DiscoveryRepository;
import com.otilm.core.dao.repository.GroupAssociationRepository;
import com.otilm.core.dao.repository.GroupRepository;
import com.otilm.core.dao.repository.RaProfileRepository;
import com.otilm.core.dao.repository.ScheduledJobsRepository;
import com.otilm.core.dao.repository.notifications.NotificationInstanceReferenceRepository;
import com.otilm.core.dao.repository.notifications.PendingNotificationRepository;
import com.otilm.core.dao.repository.workflows.EventHistoryRepository;
import com.otilm.core.dao.repository.workflows.TriggerAssociationRepository;
import com.otilm.core.dao.repository.workflows.TriggerHistoryRecordRepository;
import com.otilm.core.dao.repository.workflows.TriggerHistoryRepository;
import com.otilm.core.dao.repository.workflows.TriggerRepository;
import com.otilm.core.enums.FilterField;
import com.otilm.core.events.data.DiscoveryResult;
import com.otilm.core.events.data.EventDataBuilder;
import com.otilm.core.events.handlers.ApprovalClosedEventHandler;
import com.otilm.core.events.handlers.ApprovalRequestedEventHandler;
import com.otilm.core.events.handlers.CertificateActionPerformedEventHandler;
import com.otilm.core.events.handlers.CertificateDiscoveredEventHandler;
import com.otilm.core.events.handlers.CertificateStatusChangedEventHandler;
import com.otilm.core.events.handlers.CertificateUploadedEventHandler;
import com.otilm.core.events.handlers.DiscoveryFinishedEventHandler;
import com.otilm.core.events.handlers.ScheduledJobFinishedEventHandler;
import com.otilm.core.helpers.CertificateGeneratorHelper;
import com.otilm.core.messaging.jms.listeners.NotificationListener;
import com.otilm.core.messaging.jms.producers.EventProducer;
import com.otilm.core.messaging.model.CertificateUploadEventMessageData;
import com.otilm.core.messaging.model.EventMessage;
import com.otilm.core.messaging.model.NotificationMessage;
import com.otilm.core.messaging.model.NotificationRecipient;
import com.otilm.core.model.ScheduledTaskResult;
import com.otilm.core.model.auth.ResourceAction;
import com.otilm.core.service.ActionExternalService;
import com.otilm.core.service.ApprovalProfileExternalService;
import com.otilm.core.service.CertificateEventHistoryExternalService;
import com.otilm.core.service.NotificationProfileExternalService;
import com.otilm.core.service.ResourceObjectAssociationService;
import com.otilm.core.service.RuleExternalService;
import com.otilm.core.service.TriggerExternalService;
import com.otilm.core.service.handler.CertificateHandler;
import com.otilm.core.service.impl.CertificateServiceImpl;
import com.otilm.core.tasks.DiscoveryCertificateTask;
import com.otilm.core.util.AuthHelper;
import com.otilm.core.util.AuthServiceWireMockStubs;
import com.otilm.core.util.BaseSpringBootTest;
import com.otilm.core.util.CertificateUtil;
import com.otilm.core.util.WireMockPorts;
import com.otilm.core.util.X509ObjectToString;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.time.OffsetDateTime;
import java.time.temporal.ChronoUnit;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Date;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.test.context.bean.override.mockito.MockitoSpyBean;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyList;
import static org.mockito.Mockito.argThat;
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.reset;
import static org.mockito.Mockito.verify;

class EventHandlersITest extends BaseSpringBootTest {

    public static final String CERTIFICATE_CUSTOM_ATTRIBUTE_UUID = UUID.randomUUID().toString();
    public static final String CERTIFICATE_CUSTOM_ATTRIBUTE_NAME = "category";
    @Autowired
    private TriggerRepository triggerRepository;

    @Autowired
    private CertificateServiceImpl certificateService;
    @Autowired
    private CertificateEventHistoryExternalService certificateEventHistoryService;
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
    private GroupAssociationRepository groupAssociationRepository;
    @Autowired
    private ResourceObjectAssociationService associationService;

    @Autowired
    private ApprovalRepository approvalRepository;
    @Autowired
    private ApprovalProfileExternalService approvalProfileService;
    @Autowired
    private ApprovalClosedEventHandler approvalClosedEventHandler;
    @Autowired
    private ApprovalRequestedEventHandler approvalRequestedEventHandler;

    @Autowired
    private DiscoveryRepository discoveryRepository;
    @Autowired
    private DiscoveryFinishedEventHandler discoveryFinishedEventHandler;
    @Autowired
    private CertificateDiscoveredEventHandler certificateDiscoveredEventHandler;
    @Autowired
    private DiscoveryCertificateRepository discoveryCertificateRepository;
    @MockitoSpyBean
    private EventProducer eventProducer;

    @MockitoSpyBean
    private CertificateHandler certificateHandler;

    @Autowired
    private AttributeEngine attributeEngine;
    @Autowired
    private RuleExternalService ruleService;
    @Autowired
    private ActionExternalService actionService;
    @Autowired
    private TriggerExternalService triggerService;
    @Autowired
    private TriggerAssociationRepository triggerAssociationRepository;
    @Autowired
    private EventHistoryRepository eventHistoryRepository;
    @Autowired
    private TriggerHistoryRepository triggerHistoryRepository;

    @Autowired
    private TriggerHistoryRecordRepository triggerHistoryRecordRepository;

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

    @AfterEach
    void tearDown() {
        if (mockServer != null) {
            mockServer.stop();
        }
    }

    @Test
    void testCertificateStatusChangedAndApprovalEvents()
            throws EventException, NotFoundException, AlreadyExistException, AttributeException {
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

        createCertificateTriggerAssociation(ResourceEvent.CERTIFICATE_STATUS_CHANGED, Resource.RA_PROFILE,
                raProfile.getUuid(), false);

        certificateService.validate(certificate);
        certificateStatusChangedEventHandler
                .handleEvent(CertificateStatusChangedEventHandler
                        .constructEventMessage(certificate.getUuid(), CertificateValidationStatus.INACTIVE,
                                certificate.getValidationStatus()));
        List<CertificateEventHistoryDto> historyList = certificateEventHistoryService
                .getCertificateEventHistory(certificate.getUuid());
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

        ApprovalStepDto approvalStepDto = approvalProfile
                .getTheLatestApprovalProfileVersion()
                .getApprovalSteps()
                .getFirst()
                .mapToDto();
        approvalRequestedEventHandler
                .handleEvent(ApprovalRequestedEventHandler.constructEventMessage(approval.getUuid(), approvalStepDto));
        historyList = certificateEventHistoryService.getCertificateEventHistory(certificate.getUuid());
        Assertions.assertEquals(2, historyList.size());
        Assertions.assertEquals(CertificateEvent.APPROVAL_REQUEST, historyList.getFirst().getEvent());
        Assertions
                .assertEquals("tst-user", historyList.getFirst().getCreatedBy(),
                        "the approval-request history row must name the acting user, not the system user");

        Assertions
                .assertDoesNotThrow(() -> certificateActionPerformedEventHandler
                        .handleEvent(CertificateActionPerformedEventHandler
                                .constructEventMessage(certificate.getUuid(), ResourceAction.REVOKE)));

        approvalClosedEventHandler
                .handleEvent(ApprovalClosedEventHandler
                        .constructEventMessage(approval.getUuid(), ApprovalStatusEnum.APPROVED));
        historyList = certificateEventHistoryService.getCertificateEventHistory(certificate.getUuid());
        Assertions.assertEquals(3, historyList.size());
        Assertions.assertEquals(CertificateEvent.APPROVAL_CLOSE, historyList.getFirst().getEvent());
        Assertions
                .assertEquals("tst-user", historyList.getFirst().getCreatedBy(),
                        "the approval-close history row must name the approving user, not the system user");
    }

    private void createCertificateTriggerAssociation(ResourceEvent event, Resource eventResource, UUID eventObjectUuid,
            boolean ignoreTrigger) throws AttributeException, AlreadyExistException, NotFoundException {
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
            executionItemRequest
                    .setFieldIdentifier("%s|%s".formatted(certAttr.getName(), certAttr.getContentType().name()));
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
        mockServer = new WireMockServer(WireMockPorts.AUTH_SERVICE);
        mockServer.start();
        WireMock.configureFor("localhost", mockServer.port());

        NameAndUuidDto userInfo = AuthHelper.getUserIdentification();
        mockAuthResponse(userInfo);

        // associate trigger with RA profile for CERTIFICATE_STATUS_CHANGED
        triggerService
                .createTriggerAssociations(event, eventResource, eventObjectUuid,
                        List.of(UUID.fromString(trigger.getUuid())), true);
    }

    private void createCertificateUploadedCustomAttributeIgnoreTrigger(String attributeName,
            FilterConditionOperator operator, String matchValue)
            throws AlreadyExistException, NotFoundException, AttributeException {
        CustomAttributeV3 certAttr = new CustomAttributeV3();
        certAttr.setUuid(UUID.randomUUID().toString());
        certAttr.setName(attributeName);
        certAttr.setType(AttributeType.CUSTOM);
        certAttr.setContentType(AttributeContentType.STRING);
        CustomAttributeProperties customProps = new CustomAttributeProperties();
        customProps.setLabel(attributeName);
        certAttr.setProperties(customProps);
        attributeEngine.updateCustomAttributeDefinition(certAttr, List.of(Resource.CERTIFICATE));

        ConditionItemRequestDto conditionItemRequest = new ConditionItemRequestDto();
        conditionItemRequest.setFieldSource(FilterFieldSource.CUSTOM);
        conditionItemRequest.setFieldIdentifier("%s|%s".formatted(attributeName, AttributeContentType.STRING.name()));
        conditionItemRequest.setOperator(operator);
        conditionItemRequest.setValue(matchValue);

        ConditionRequestDto conditionRequest = new ConditionRequestDto();
        conditionRequest.setName("CustomAttributeUploadCondition");
        conditionRequest.setResource(Resource.CERTIFICATE);
        conditionRequest.setType(ConditionType.CHECK_FIELD);
        conditionRequest.setItems(List.of(conditionItemRequest));
        ConditionDto condition = ruleService.createCondition(conditionRequest);

        RuleRequestDto ruleRequest = new RuleRequestDto();
        ruleRequest.setName("CustomAttributeUploadRule");
        ruleRequest.setResource(Resource.CERTIFICATE);
        ruleRequest.setConditionsUuids(List.of(condition.getUuid()));
        RuleDetailDto rule = ruleService.createRule(ruleRequest);

        TriggerRequestDto triggerRequest = new TriggerRequestDto();
        triggerRequest.setName("RejectOnCustomAttributeUploadTrigger");
        triggerRequest.setType(TriggerType.EVENT);
        triggerRequest.setEvent(ResourceEvent.CERTIFICATE_UPLOADED);
        triggerRequest.setResource(Resource.CERTIFICATE);
        triggerRequest.setRulesUuids(List.of(rule.getUuid()));
        triggerRequest.setIgnoreTrigger(true);
        TriggerDetailDto trigger = triggerService.createTrigger(triggerRequest);

        mockServer = new WireMockServer(WireMockPorts.AUTH_SERVICE);
        mockServer.start();
        WireMock.configureFor("localhost", mockServer.port());
        NameAndUuidDto userInfo = AuthHelper.getUserIdentification();
        mockAuthResponse(userInfo);

        triggerService
                .createTriggerAssociations(ResourceEvent.CERTIFICATE_UPLOADED, null, null,
                        List.of(UUID.fromString(trigger.getUuid())), true);
    }

    @Test
    void testCertificateUploadedEventCustomAttributeConditionIgnoresUpload() throws Exception {
        createCertificateUploadedCustomAttributeIgnoreTrigger("criticality", FilterConditionOperator.EQUALS, "Low");

        X509Certificate certificate = CertificateGeneratorHelper.generateCACertificate(null, "CN=test");
        String fingerprint = CertificateUtil.getThumbprint(certificate);

        RequestAttributeV3 criticalityAttribute = new RequestAttributeV3();
        criticalityAttribute.setUuid(UUID.randomUUID());
        criticalityAttribute.setName("criticality");
        criticalityAttribute.setContentType(AttributeContentType.STRING);
        criticalityAttribute.setContent(List.of(new StringAttributeContentV3("Low")));

        final CertificateUploadEventMessageData eventMessageData = CertificateUploadEventMessageData
                .builder()
                .certificateContent(Base64.getEncoder().encodeToString(certificate.getEncoded()))
                .customAttributes(List.of(criticalityAttribute))
                .build();

        Assertions
                .assertDoesNotThrow(() -> certificateUploadedEventHandler
                        .handleEvent(CertificateUploadedEventHandler.constructEventMessage(eventMessageData)));

        // The ignore-trigger matched the custom attribute supplied in the request — the attribute was never persisted
        // anywhere,
        // and the certificate itself was never saved either, so this proves the CUSTOM condition evaluated against
        // request content.
        Assertions.assertFalse(certificateRepository.findByFingerprint(fingerprint).isPresent());

        List<TriggerHistory> histories = triggerHistoryRepository.findAll();
        Assertions.assertEquals(1, histories.size());
        Assertions.assertTrue(histories.getFirst().isConditionsMatched());
        Assertions.assertTrue(histories.getFirst().isActionsPerformed());
    }

    @Test
    void testCertificateUploadedEventCustomAttributeEmptyConditionIgnoresUploadWithNoAttributes() throws Exception {
        // Ignore-trigger fires when "criticality" is EMPTY — i.e. the upload didn't specify it at all.
        createCertificateUploadedCustomAttributeIgnoreTrigger("criticality", FilterConditionOperator.EMPTY, null);

        X509Certificate certificate = CertificateGeneratorHelper.generateCACertificate(null, "CN=test");
        String fingerprint = CertificateUtil.getThumbprint(certificate);

        // No customAttributes at all in the upload payload — eventMessageData.customAttributes() is null.
        final CertificateUploadEventMessageData eventMessageData = CertificateUploadEventMessageData
                .builder()
                .certificateContent(Base64.getEncoder().encodeToString(certificate.getEncoded()))
                .build();

        Assertions
                .assertDoesNotThrow(() -> certificateUploadedEventHandler
                        .handleEvent(CertificateUploadedEventHandler.constructEventMessage(eventMessageData)));

        // The EMPTY condition matched because no attribute was supplied at all — proves CertificateUploadedEventHandler
        // normalizes a null customAttributes() to an empty list rather than passing null through to the evaluator.
        Assertions.assertFalse(certificateRepository.findByFingerprint(fingerprint).isPresent());

        List<TriggerHistory> histories = triggerHistoryRepository.findAll();
        Assertions.assertEquals(1, histories.size());
        Assertions.assertTrue(histories.getFirst().isConditionsMatched());
        Assertions.assertTrue(histories.getFirst().isActionsPerformed());
    }

    @Test
    void testProcessTriggersExceptionSetsEventHistoryToFailed() throws EventException {
        Discovery discovery = new Discovery();
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

        // No auth service is running on port 10001, so authenticateAsUser throws PlatformAuthenticationException,
        // which escapes handleUser (catches only ValidationException) and is caught by the outer catch in
        // processTriggers (EventHandler line 208), which sets EventStatus.FAILED on the event history.
        discoveryFinishedEventHandler
                .handleEvent(DiscoveryFinishedEventHandler
                        .constructEventMessage(discovery.getUuid(), null, null,
                                new DiscoveryResult(DiscoveryStatus.COMPLETED, "Test")));

        List<EventHistory> eventHistories = eventHistoryRepository.findAll();
        Assertions.assertEquals(1, eventHistories.size());
        Assertions.assertEquals(EventStatus.FAILED, eventHistories.getFirst().getStatus());
        Assertions.assertNotNull(eventHistories.getFirst().getFinishedAt());
    }

    @Test
    void testDiscoveryFinishedEventCompletesProcessingDiscovery() throws EventException {
        Discovery discovery = persistProcessingDiscovery();

        discoveryFinishedEventHandler
                .handleEvent(DiscoveryFinishedEventHandler
                        .constructEventMessage(discovery.getUuid(), null, null,
                                new DiscoveryResult(DiscoveryStatus.PROCESSING, "Provider completed.")));

        Discovery persisted = discoveryRepository.findByUuid(discovery.getUuid()).orElseThrow();
        Assertions.assertEquals(DiscoveryStatus.COMPLETED, persisted.getStatus());
        Assertions.assertNotNull(persisted.getEndTime());
        Assertions.assertEquals("Discovery completed successfully. Provider completed.", persisted.getMessage());
    }

    @Test
    void testDiscoveryFinishedEventLeavesACancelledDiscoveryAlone() throws EventException {
        Discovery discovery = persistProcessingDiscovery();
        discovery.setStatus(DiscoveryStatus.CANCELLED);
        discovery.setMessage("Discovery cancelled");
        discoveryRepository.save(discovery);

        discoveryFinishedEventHandler
                .handleEvent(DiscoveryFinishedEventHandler
                        .constructEventMessage(discovery.getUuid(), null, null,
                                new DiscoveryResult(DiscoveryStatus.PROCESSING, "Provider completed.")));

        // A cancel is final. Post-processing that was already in flight when the run was cancelled must not
        // resurrect it as COMPLETED.
        Discovery persisted = discoveryRepository.findByUuid(discovery.getUuid()).orElseThrow();
        Assertions.assertEquals(DiscoveryStatus.CANCELLED, persisted.getStatus());
        Assertions.assertEquals("Discovery cancelled", persisted.getMessage());
    }

    @Test
    void testDiscoveryFinishedEventMarksWarningWhenCertificatesFailed() throws EventException {
        Discovery discovery = persistProcessingDiscovery();

        discoveryFinishedEventHandler
                .handleEvent(DiscoveryFinishedEventHandler
                        .constructEventMessage(discovery.getUuid(), null, null, new DiscoveryResult(
                                DiscoveryStatus.WARNING, "2 certificate(s) could not be processed during discovery.")));

        Discovery persisted = discoveryRepository.findByUuid(discovery.getUuid()).orElseThrow();
        Assertions.assertEquals(DiscoveryStatus.WARNING, persisted.getStatus());
        Assertions.assertNotNull(persisted.getEndTime());
        Assertions
                .assertEquals(
                        "Discovery completed with warnings. 2 certificate(s) could not be processed during discovery.",
                        persisted.getMessage());
    }

    @Test
    void testDiscoveryFinishedEventIgnoresNonFinishSignal() throws EventException {
        Discovery discovery = persistProcessingDiscovery();

        // COMPLETED/FAILED payloads come from the discovery service with the state already persisted; only a
        // PROCESSING or WARNING signal from certificate post-processing finalizes a processing discovery.
        discoveryFinishedEventHandler
                .handleEvent(DiscoveryFinishedEventHandler
                        .constructEventMessage(discovery.getUuid(), null, null,
                                new DiscoveryResult(DiscoveryStatus.FAILED, "Provider failed.")));

        Discovery persisted = discoveryRepository.findByUuid(discovery.getUuid()).orElseThrow();
        Assertions.assertEquals(DiscoveryStatus.PROCESSING, persisted.getStatus());
        Assertions.assertNull(persisted.getEndTime());
    }

    @Test
    void testDiscoveryFinishedEventLeavesTerminalDiscoveryUnchanged() throws EventException {
        Discovery discovery = persistProcessingDiscovery();
        discovery.setStatus(DiscoveryStatus.COMPLETED);
        discovery.setEndTime(OffsetDateTime.now());
        discovery.setMessage("Discovery completed successfully.");
        discoveryRepository.save(discovery);
        OffsetDateTime endTimeBefore = discoveryRepository.findByUuid(discovery.getUuid()).orElseThrow().getEndTime();

        discoveryFinishedEventHandler
                .handleEvent(DiscoveryFinishedEventHandler
                        .constructEventMessage(discovery.getUuid(), null, null,
                                new DiscoveryResult(DiscoveryStatus.COMPLETED, "Late duplicate event.")));

        Discovery persisted = discoveryRepository.findByUuid(discovery.getUuid()).orElseThrow();
        Assertions.assertEquals(DiscoveryStatus.COMPLETED, persisted.getStatus());
        Assertions.assertEquals(endTimeBefore, persisted.getEndTime());
        Assertions.assertEquals("Discovery completed successfully.", persisted.getMessage());
    }

    @Test
    void testCertificateDiscoveredEmitsFinishWhenNoNewCertificates() throws EventException {
        Discovery discovery = persistProcessingDiscovery();

        certificateDiscoveredEventHandler
                .handleEvent(CertificateDiscoveredEventHandler.constructEventMessage(discovery.getUuid(), null, null));

        verify(eventProducer)
                .produceMessage(argThat((EventMessage msg) -> msg.getEvent() == ResourceEvent.DISCOVERY_FINISHED
                        && discovery.getUuid().equals(msg.getObjectUuid())
                        && ((DiscoveryResult) msg.getData()).getDiscoveryStatus() == DiscoveryStatus.PROCESSING));
    }

    @Test
    void testCertificateDiscoveredEmitsWarningWhenCertificateProcessingFails() throws EventException {
        Discovery discovery = persistProcessingDiscovery();

        CertificateContent certificateContent = new CertificateContent();
        certificateContent.setContent("not-a-valid-certificate");
        certificateContent = certificateContentRepository.save(certificateContent);

        DiscoveryCertificate discoveryCertificate = new DiscoveryCertificate();
        discoveryCertificate.setCommonName("failing-cert");
        discoveryCertificate.setNewlyDiscovered(true);
        discoveryCertificate.setCertificateContent(certificateContent);
        discoveryCertificate.setDiscovery(discovery);
        discoveryCertificateRepository.save(discoveryCertificate);

        certificateDiscoveredEventHandler
                .handleEvent(CertificateDiscoveredEventHandler.constructEventMessage(discovery.getUuid(), null, null));

        verify(eventProducer)
                .produceMessage(argThat((EventMessage msg) -> msg.getEvent() == ResourceEvent.DISCOVERY_FINISHED
                        && discovery.getUuid().equals(msg.getObjectUuid())
                        && ((DiscoveryResult) msg.getData()).getDiscoveryStatus() == DiscoveryStatus.WARNING));
        DiscoveryCertificate processed = discoveryCertificateRepository
                .findByUuid(discoveryCertificate.getUuid())
                .orElseThrow();
        Assertions.assertNotNull(processed.getProcessedError());
    }

    private Discovery persistProcessingDiscovery() {
        Discovery discovery = new Discovery();
        discovery.setName("TestDiscovery");
        discovery.setKind("IP");
        discovery.setStatus(DiscoveryStatus.PROCESSING);
        discovery.setConnectorUuid(UUID.randomUUID());
        discovery.setConnectorStatus(DiscoveryStatus.COMPLETED);
        return discoveryRepository.save(discovery);
    }

    /**
     * Several rows carrying the same certificate must produce one certificate and no rollback. Left to race on an
     * unguarded find-then-insert, all but one roll back and take the certificate and the record of why with them.
     */
    @Test
    void testCertificateDiscoveredImportsOneCertificateForDuplicateRows() throws Exception {
        Discovery discovery = persistProcessingDiscovery();
        X509Certificate x509 = generateSelfSignedCertificate();
        CertificateContent content = persistContentFor(x509);
        List<DiscoveryCertificate> rows = List
                .of(persistDiscoveryCertificate(discovery, content, "host-one"),
                        persistDiscoveryCertificate(discovery, content, "host-two"),
                        persistDiscoveryCertificate(discovery, content, "host-three"));

        certificateDiscoveredEventHandler
                .handleEvent(CertificateDiscoveredEventHandler.constructEventMessage(discovery.getUuid(), null, null));

        Assertions
                .assertTrue(certificateRepository.findByFingerprint(CertificateUtil.getThumbprint(x509)).isPresent(),
                        "the group must yield exactly one certificate");
        Assertions
                .assertEquals(1,
                        certificateRepository
                                .findAll()
                                .stream()
                                .filter(certificate -> content.getId().equals(certificate.getCertificateContentId()))
                                .count(),
                        "no duplicate certificate rows for one content");
        for (DiscoveryCertificate row : rows) {
            DiscoveryCertificate reloaded = discoveryCertificateRepository.findByUuid(row.getUuid()).orElseThrow();
            Assertions.assertTrue(reloaded.isProcessed(), "every row in the group must be marked processed");
            Assertions
                    .assertNull(reloaded.getProcessedError(),
                            "a deduplicated row is not a failure: " + reloaded.getProcessedError());
        }
        verify(eventProducer)
                .produceMessage(argThat((EventMessage msg) -> msg.getEvent() == ResourceEvent.DISCOVERY_FINISHED
                        && ((DiscoveryResult) msg.getData()).getDiscoveryStatus() == DiscoveryStatus.PROCESSING));
    }

    /**
     * An action trigger whose execution fails must not cost the discovery its certificates. This execution fails
     * checked, so it exercises the containment and the surviving history, not the rollback-only path — no execution
     * reachable from here produces that.
     */
    @Test
    void testCertificateDiscoveredImportsWhenAnActionTriggerExecutionFails() throws Exception {
        Discovery discovery = persistProcessingDiscovery();
        X509Certificate x509 = generateSelfSignedCertificate();
        CertificateContent content = persistContentFor(x509);
        DiscoveryCertificate row = persistDiscoveryCertificate(discovery, content, "action-failing-host");
        createFailingSetFieldActionTrigger(discovery.getUuid());

        certificateDiscoveredEventHandler
                .handleEvent(CertificateDiscoveredEventHandler.constructEventMessage(discovery.getUuid(), null, null));

        Certificate imported = certificateRepository
                .findByFingerprint(CertificateUtil.getThumbprint(x509))
                .orElseThrow(() -> new AssertionError("a failing action trigger must not roll back the certificate"));
        DiscoveryCertificate reloaded = discoveryCertificateRepository.findByUuid(row.getUuid()).orElseThrow();
        Assertions.assertTrue(reloaded.isProcessed());
        Assertions
                .assertNull(reloaded.getProcessedError(),
                        "an action failure belongs in trigger history, not on the discovered row: "
                                + reloaded.getProcessedError());
        // Asserted positively: every check above also holds when the trigger never ran at all, so without this the
        // test would pass on a mis-scoped association or an early return.
        List<TriggerHistory> histories = triggerHistoryRepository
                .findAll()
                .stream()
                .filter(history -> imported.getUuid().equals(history.getObjectUuid()))
                .toList();
        Assertions
                .assertEquals(1, histories.size(),
                        "the configured trigger must have been evaluated against the imported certificate");
        Assertions
                .assertFalse(histories.getFirst().isActionsPerformed(),
                        "its execution failed, so the history must say the actions were not applied");
        Assertions
                .assertTrue(
                        triggerHistoryRecordRepository
                                .findAll()
                                .stream()
                                .anyMatch(historyRecord -> histories
                                        .getFirst()
                                        .getUuid()
                                        .equals(historyRecord.getTriggerHistoryUuid())),
                        "and must carry a record naming the failure");
        Assertions
                .assertNull(imported.getRaProfile(),
                        "the execution failed, so the RA profile it tried to set must not be applied");
        verify(eventProducer)
                .produceMessage(argThat((EventMessage msg) -> msg.getEvent() == ResourceEvent.DISCOVERY_FINISHED
                        && ((DiscoveryResult) msg.getData()).getDiscoveryStatus() == DiscoveryStatus.PROCESSING));
    }

    /**
     * The load-bearing half of running actions after the import: the certificate is re-resolved in the trigger's own
     * transaction, so an execution's write persists. A broken re-resolution passes every failing-execution test.
     */
    @Test
    void testCertificateDiscoveredAppliesASucceedingActionTriggerAcrossTheTransactionBoundary() throws Exception {
        Discovery discovery = persistProcessingDiscovery();
        X509Certificate x509 = generateSelfSignedCertificate();
        CertificateContent content = persistContentFor(x509);
        persistDiscoveryCertificate(discovery, content, "group-setting-host");
        Group group = new Group();
        group.setName("DiscoveredCertificates");
        group = groupRepository.save(group);
        UUID groupUuid = group.getUuid();
        createSetGroupActionTrigger(discovery.getUuid(), groupUuid);

        certificateDiscoveredEventHandler
                .handleEvent(CertificateDiscoveredEventHandler.constructEventMessage(discovery.getUuid(), null, null));

        Certificate imported = certificateRepository
                .findByFingerprint(CertificateUtil.getThumbprint(x509))
                .orElseThrow();
        List<GroupAssociation> associations = groupAssociationRepository
                .findByResourceAndObjectUuid(Resource.CERTIFICATE, imported.getUuid());
        Assertions.assertEquals(1, associations.size(), "the execution's write must survive the transaction it ran in");
        Assertions.assertEquals(groupUuid, associations.getFirst().getGroupUuid());
    }

    /**
     * A failing trigger costs only itself; a shared transaction would lose the writes of those that succeeded. This one
     * fails checked, so the isolation itself is pinned by {@code eachActionTriggerGetsItsOwnTransaction}.
     */
    @Test
    void testCertificateDiscoveredKeepsASucceedingTriggerWhenAnotherFails() throws Exception {
        Discovery discovery = persistProcessingDiscovery();
        X509Certificate x509 = generateSelfSignedCertificate();
        CertificateContent content = persistContentFor(x509);
        persistDiscoveryCertificate(discovery, content, "two-trigger-host");
        Group group = new Group();
        group.setName("SurvivesTheOtherFailure");
        group = groupRepository.save(group);
        // The succeeding trigger first: the property at risk is that an earlier success survives a later failure.
        createSetGroupActionTrigger(discovery.getUuid(), group.getUuid());
        createFailingSetFieldActionTrigger(discovery.getUuid());

        certificateDiscoveredEventHandler
                .handleEvent(CertificateDiscoveredEventHandler.constructEventMessage(discovery.getUuid(), null, null));

        Certificate imported = certificateRepository
                .findByFingerprint(CertificateUtil.getThumbprint(x509))
                .orElseThrow();
        Assertions
                .assertEquals(1,
                        groupAssociationRepository
                                .findByResourceAndObjectUuid(Resource.CERTIFICATE, imported.getUuid())
                                .size(),
                        "the succeeding trigger's write must not be discarded by the failing one");
        Assertions.assertNull(imported.getRaProfile(), "the failing execution must still not apply");
    }

    private void createSetGroupActionTrigger(UUID discoveryUuid, UUID groupUuid)
            throws AlreadyExistException, NotFoundException {
        ExecutionItemRequestDto executionItemRequest = new ExecutionItemRequestDto();
        executionItemRequest.setFieldSource(FilterFieldSource.PROPERTY);
        executionItemRequest.setFieldIdentifier(FilterField.GROUP_NAME.name());
        executionItemRequest.setData(groupUuid.toString());

        ExecutionRequestDto executionRequest = new ExecutionRequestDto();
        executionRequest.setName("SetDiscoveredGroup");
        executionRequest.setResource(Resource.CERTIFICATE);
        executionRequest.setType(ExecutionType.SET_FIELD);
        executionRequest.setItems(List.of(executionItemRequest));
        ExecutionDto execution = actionService.createExecution(executionRequest);

        ActionRequestDto actionRequest = new ActionRequestDto();
        actionRequest.setName("SetDiscoveredGroupAction");
        actionRequest.setResource(Resource.CERTIFICATE);
        actionRequest.setExecutionsUuids(List.of(execution.getUuid()));
        ActionDetailDto action = actionService.createAction(actionRequest);

        TriggerRequestDto triggerRequest = new TriggerRequestDto();
        triggerRequest.setName("SetDiscoveredGroupTrigger");
        triggerRequest.setType(TriggerType.EVENT);
        triggerRequest.setEvent(ResourceEvent.CERTIFICATE_DISCOVERED);
        triggerRequest.setResource(Resource.CERTIFICATE);
        triggerRequest.setActionsUuids(List.of(action.getUuid()));
        TriggerDetailDto trigger = triggerService.createTrigger(triggerRequest);

        triggerService
                .createTriggerAssociations(ResourceEvent.CERTIFICATE_DISCOVERED, Resource.DISCOVERY, discoveryUuid,
                        List.of(UUID.fromString(trigger.getUuid())), false);
    }

    /**
     * A SET_FIELD execution switching the RA profile to one that has no authority instance — reachable configuration,
     * so the execution fails inside the RA-profile switch.
     */
    private void createFailingSetFieldActionTrigger(UUID discoveryUuid)
            throws AlreadyExistException, NotFoundException {
        RaProfile raProfile = new RaProfile();
        raProfile.setName("ra-profile-without-authority");
        raProfile = raProfileRepository.save(raProfile);

        ExecutionItemRequestDto executionItemRequest = new ExecutionItemRequestDto();
        executionItemRequest.setFieldSource(FilterFieldSource.PROPERTY);
        executionItemRequest.setFieldIdentifier(FilterField.RA_PROFILE_NAME.name());
        executionItemRequest.setData(raProfile.getUuid().toString());

        ExecutionRequestDto executionRequest = new ExecutionRequestDto();
        executionRequest.setName("SwitchToAuthoritylessRaProfile");
        executionRequest.setResource(Resource.CERTIFICATE);
        executionRequest.setType(ExecutionType.SET_FIELD);
        executionRequest.setItems(List.of(executionItemRequest));
        ExecutionDto execution = actionService.createExecution(executionRequest);

        ActionRequestDto actionRequest = new ActionRequestDto();
        actionRequest.setName("SwitchRaProfileAction");
        actionRequest.setResource(Resource.CERTIFICATE);
        actionRequest.setExecutionsUuids(List.of(execution.getUuid()));
        ActionDetailDto action = actionService.createAction(actionRequest);

        TriggerRequestDto triggerRequest = new TriggerRequestDto();
        triggerRequest.setName("SwitchRaProfileTrigger");
        triggerRequest.setType(TriggerType.EVENT);
        triggerRequest.setEvent(ResourceEvent.CERTIFICATE_DISCOVERED);
        triggerRequest.setResource(Resource.CERTIFICATE);
        triggerRequest.setActionsUuids(List.of(action.getUuid()));
        TriggerDetailDto trigger = triggerService.createTrigger(triggerRequest);

        mockServer = new WireMockServer(WireMockPorts.AUTH_SERVICE);
        mockServer.start();
        WireMock.configureFor("localhost", mockServer.port());
        mockAuthResponse(AuthHelper.getUserIdentification());

        triggerService
                .createTriggerAssociations(ResourceEvent.CERTIFICATE_DISCOVERED, Resource.DISCOVERY, discoveryUuid,
                        List.of(UUID.fromString(trigger.getUuid())), false);
    }

    /**
     * An ignore trigger conditioned on the fingerprint must keep the certificate out of the inventory.
     *
     * <p>
     * The candidate the ignore triggers evaluate is built in memory, so every field a rule can read has to be stamped
     * on it explicitly. Miss the fingerprint and the condition reads null: the evaluator records a failed condition and
     * swallows it, so the rule silently stops matching and the certificate is imported anyway — no exception, no
     * warning, nothing but a trigger-history note.
     */
    @Test
    void testCertificateDiscoveredHonoursAnIgnoreTriggerConditionedOnTheFingerprint() throws Exception {
        Discovery discovery = persistProcessingDiscovery();
        X509Certificate x509 = generateSelfSignedCertificate();
        String fingerprint = CertificateUtil.getThumbprint(x509);
        CertificateContent content = persistContentFor(x509);
        DiscoveryCertificate row = persistDiscoveryCertificate(discovery, content, "ignored-host");
        createFingerprintIgnoreTrigger(discovery.getUuid(), fingerprint);

        certificateDiscoveredEventHandler
                .handleEvent(CertificateDiscoveredEventHandler.constructEventMessage(discovery.getUuid(), null, null));

        Assertions
                .assertFalse(certificateRepository.findByFingerprint(fingerprint).isPresent(),
                        "the ignore trigger matched on the fingerprint, so nothing may be imported");
        DiscoveryCertificate reloaded = discoveryCertificateRepository.findByUuid(row.getUuid()).orElseThrow();
        Assertions.assertTrue(reloaded.isProcessed(), "an ignored row is still handled");
        Assertions.assertNull(reloaded.getProcessedError(), "being ignored is not a failure");
        verify(eventProducer)
                .produceMessage(argThat((EventMessage msg) -> msg.getEvent() == ResourceEvent.DISCOVERY_FINISHED
                        && ((DiscoveryResult) msg.getData()).getDiscoveryStatus() == DiscoveryStatus.PROCESSING));
    }

    private void createFingerprintIgnoreTrigger(UUID discoveryUuid, String fingerprint)
            throws AlreadyExistException, NotFoundException {
        createPropertyIgnoreTrigger(discoveryUuid, FilterField.FINGERPRINT, FilterConditionOperator.EQUALS,
                fingerprint);
    }

    private void createPropertyIgnoreTrigger(UUID discoveryUuid, FilterField field, FilterConditionOperator operator,
            Object value) throws AlreadyExistException, NotFoundException {
        ConditionItemRequestDto conditionItemRequest = new ConditionItemRequestDto();
        conditionItemRequest.setFieldSource(FilterFieldSource.PROPERTY);
        conditionItemRequest.setFieldIdentifier(field.name());
        conditionItemRequest.setOperator(operator);
        conditionItemRequest.setValue(value);

        ConditionRequestDto conditionRequest = new ConditionRequestDto();
        conditionRequest.setName("FingerprintEqualsCondition");
        conditionRequest.setResource(Resource.CERTIFICATE);
        conditionRequest.setType(ConditionType.CHECK_FIELD);
        conditionRequest.setItems(List.of(conditionItemRequest));
        ConditionDto condition = ruleService.createCondition(conditionRequest);

        RuleRequestDto ruleRequest = new RuleRequestDto();
        ruleRequest.setName("FingerprintEqualsRule");
        ruleRequest.setResource(Resource.CERTIFICATE);
        ruleRequest.setConditionsUuids(List.of(condition.getUuid()));
        RuleDetailDto rule = ruleService.createRule(ruleRequest);

        TriggerRequestDto triggerRequest = new TriggerRequestDto();
        triggerRequest.setName("IgnoreByFingerprintTrigger");
        triggerRequest.setType(TriggerType.EVENT);
        triggerRequest.setEvent(ResourceEvent.CERTIFICATE_DISCOVERED);
        triggerRequest.setResource(Resource.CERTIFICATE);
        triggerRequest.setRulesUuids(List.of(rule.getUuid()));
        triggerRequest.setActionsUuids(List.of());
        triggerRequest.setIgnoreTrigger(true);
        TriggerDetailDto trigger = triggerService.createTrigger(triggerRequest);

        mockServer = new WireMockServer(WireMockPorts.AUTH_SERVICE);
        mockServer.start();
        WireMock.configureFor("localhost", mockServer.port());
        mockAuthResponse(AuthHelper.getUserIdentification());

        triggerService
                .createTriggerAssociations(ResourceEvent.CERTIFICATE_DISCOVERED, Resource.DISCOVERY, discoveryUuid,
                        List.of(UUID.fromString(trigger.getUuid())), true);
    }

    /**
     * A property condition reading through an association the certificate does not have must not cost the import. A
     * discovered certificate has no RA profile, so resolving {@code raProfile.name} throws unchecked — and because the
     * evaluator is {@code @Transactional}, that used to mark the group's transaction rollback-only past any catch here.
     * Every group evaluates the same triggers, so one such rule imported nothing at all.
     */
    @Test
    void testCertificateDiscoveredImportsDespiteAConditionOnAnAbsentAssociation() throws Exception {
        Discovery discovery = persistProcessingDiscovery();
        X509Certificate x509 = generateSelfSignedCertificate();
        CertificateContent content = persistContentFor(x509);
        DiscoveryCertificate row = persistDiscoveryCertificate(discovery, content, "no-ra-profile-host");
        createPropertyIgnoreTrigger(discovery.getUuid(), FilterField.RA_PROFILE_NAME, FilterConditionOperator.EMPTY,
                null);

        certificateDiscoveredEventHandler
                .handleEvent(CertificateDiscoveredEventHandler.constructEventMessage(discovery.getUuid(), null, null));

        Assertions
                .assertTrue(certificateRepository.findByFingerprint(CertificateUtil.getThumbprint(x509)).isPresent(),
                        "an unevaluable condition must not cost the certificate its import");
        DiscoveryCertificate reloaded = discoveryCertificateRepository.findByUuid(row.getUuid()).orElseThrow();
        Assertions.assertTrue(reloaded.isProcessed());
        Assertions.assertNull(reloaded.getProcessedError(), "unexpected reason: " + reloaded.getProcessedError());
        verify(eventProducer)
                .produceMessage(argThat((EventMessage msg) -> msg.getEvent() == ResourceEvent.DISCOVERY_FINISHED
                        && ((DiscoveryResult) msg.getData()).getDiscoveryStatus() == DiscoveryStatus.PROCESSING));
    }

    /**
     * A group whose import rolls back must record why on every one of its rows — the reason has to survive the failure
     * that produced it — and must not also be counted as a missing key association.
     *
     * <p>
     * The failure is the production one, not an injected stub: an existing certificate already occupies this content id
     * under a different fingerprint, so the group's insert violates the unique constraint on
     * {@code certificate_content_id} — the same constraint whose violation loses certificates in the field.
     */
    @Test
    void testCertificateDiscoveredRecordsARolledBackGroupWithoutCountingItAsAKeyGap() throws Exception {
        Discovery discovery = persistProcessingDiscovery();
        X509Certificate x509 = generateSelfSignedCertificate();
        CertificateContent content = persistContentFor(x509);
        DiscoveryCertificate row = persistDiscoveryCertificate(discovery, content, "rolling-back-host");
        occupyContentIdWithAnotherCertificate(content);

        certificateDiscoveredEventHandler
                .handleEvent(CertificateDiscoveredEventHandler.constructEventMessage(discovery.getUuid(), null, null));

        DiscoveryCertificate reloaded = discoveryCertificateRepository.findByUuid(row.getUuid()).orElseThrow();
        Assertions
                .assertTrue(reloaded.isProcessed(),
                        "the outcome must be recorded even though the import transaction failed");
        Assertions.assertNotNull(reloaded.getProcessedError(), "the row must carry the reason");
        // The specific reason, not merely a non-null one: returning a shaped result from a transaction already
        // marked rollback-only lets the commit's own generic text replace it, which a non-null assertion cannot see.
        Assertions
                .assertEquals("Import rolled back: unable to create certificate entity: "
                        + "a concurrent import committed the same certificate", reloaded.getProcessedError());
        Assertions
                .assertFalse(reloaded.getProcessedError().contains("insert into"),
                        "the reason must not leak SQL: " + reloaded.getProcessedError());
        Assertions
                .assertFalse(reloaded.getProcessedError().contains("certificate_content_id"),
                        "the reason must not leak column names: " + reloaded.getProcessedError());

        verify(eventProducer).produceMessage(argThat((EventMessage msg) -> {
            if (msg.getEvent() != ResourceEvent.DISCOVERY_FINISHED) {
                return false;
            }
            DiscoveryResult result = (DiscoveryResult) msg.getData();
            return result.getDiscoveryStatus() == DiscoveryStatus.WARNING
                    && result.getMessage().contains("could not be imported into the inventory")
                    && !result.getMessage().contains("without a public key association");
        }));
    }

    /**
     * A key association that fails must be attributed to the certificate, marking every discovered row behind it and
     * counting the certificate once. The upload itself is stubbed because a failure of the cryptographic key service
     * has no natural trigger here; the surrounding wiring — accumulator re-classification, per-row reasons, and the
     * status message — is what this exercises.
     */
    @Test
    void testCertificateDiscoveredAttributesAFailedKeyAssociationToEveryRow() throws Exception {
        Discovery discovery = persistProcessingDiscovery();
        X509Certificate x509 = generateSelfSignedCertificate();
        CertificateContent content = persistContentFor(x509);
        List<DiscoveryCertificate> rows = List
                .of(persistDiscoveryCertificate(discovery, content, "host-one"),
                        persistDiscoveryCertificate(discovery, content, "host-two"));
        doReturn(false).when(certificateHandler).uploadDiscoveredCertificateKey(any(), anyList());

        try {
            certificateDiscoveredEventHandler
                    .handleEvent(
                            CertificateDiscoveredEventHandler.constructEventMessage(discovery.getUuid(), null, null));

            for (DiscoveryCertificate row : rows) {
                DiscoveryCertificate reloaded = discoveryCertificateRepository.findByUuid(row.getUuid()).orElseThrow();
                Assertions
                        .assertNotNull(reloaded.getProcessedError(),
                                "every row behind the certificate must record the failed association");
                Assertions
                        .assertTrue(reloaded.getProcessedError().contains("key could not be associated"),
                                "unexpected reason: " + reloaded.getProcessedError());
            }
            verify(eventProducer).produceMessage(argThat((EventMessage msg) -> {
                if (msg.getEvent() != ResourceEvent.DISCOVERY_FINISHED) {
                    return false;
                }
                DiscoveryResult result = (DiscoveryResult) msg.getData();
                return result.getDiscoveryStatus() == DiscoveryStatus.WARNING
                        && result
                                .getMessage()
                                .contains("1 certificate(s) were imported without all of their public keys associated")
                        && !result.getMessage().contains("could not be imported into the inventory");
            }));
        } finally {
            reset(certificateHandler);
        }
    }

    private void occupyContentIdWithAnotherCertificate(CertificateContent content) {
        Certificate squatter = new Certificate();
        squatter.setUuid(UUID.randomUUID());
        squatter.setFingerprint("squatter-" + UUID.randomUUID());
        squatter.setCertificateContentId(content.getId());
        squatter.setState(CertificateState.ISSUED);
        squatter.setValidationStatus(CertificateValidationStatus.NOT_CHECKED);
        squatter.setComplianceStatus(ComplianceStatus.NOT_CHECKED);
        squatter.setCertificateType(CertificateType.X509);
        certificateRepository.save(squatter);
    }

    private CertificateContent persistContentFor(X509Certificate x509) throws Exception {
        CertificateContent content = new CertificateContent();
        content.setFingerprint(CertificateUtil.getThumbprint(x509));
        content.setContent(CertificateUtil.normalizeCertificateContent(X509ObjectToString.toPem(x509)));
        return certificateContentRepository.save(content);
    }

    private DiscoveryCertificate persistDiscoveryCertificate(Discovery discovery, CertificateContent content,
            String host) {
        DiscoveryCertificate row = new DiscoveryCertificate();
        row.setCommonName(host);
        row.setNewlyDiscovered(true);
        row.setCertificateContent(content);
        row.setDiscovery(discovery);
        row.setDiscoveryUuid(discovery.getUuid());
        row.setMeta(List.of());
        return discoveryCertificateRepository.save(row);
    }

    private static X509Certificate generateSelfSignedCertificate() throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(2048);
        KeyPair keyPair = generator.generateKeyPair();
        X500Name subject = new X500Name("CN=discovery-group-itest-" + UUID.randomUUID());
        Instant now = Instant.now();
        X509v3CertificateBuilder builder = new JcaX509v3CertificateBuilder(subject,
                BigInteger.valueOf(now.toEpochMilli()), Date.from(now.minusSeconds(60)),
                Date.from(now.plusSeconds(86400)), subject, keyPair.getPublic());
        return new JcaX509CertificateConverter()
                .getCertificate(
                        builder.build(new JcaContentSignerBuilder("SHA256withRSA").build(keyPair.getPrivate())));
    }

    @Test
    void testDiscoveryFinishedEvent()
            throws EventException, AttributeException, AlreadyExistException, NotFoundException {
        Discovery discovery = new Discovery();
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
        executionItemRequest
                .setFieldIdentifier("%s|%s"
                        .formatted(certificateDomainAttr.getName(), certificateDomainAttr.getContentType().name()));
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

        mockServer = new WireMockServer(WireMockPorts.AUTH_SERVICE);
        mockServer.start();
        WireMock.configureFor("localhost", mockServer.port());

        mockAuthResponse(userInfo);

        triggerService
                .createTriggerAssociations(ResourceEvent.DISCOVERY_FINISHED, null, null,
                        List.of(UUID.fromString(triggerIgnore.getUuid()), UUID.fromString(trigger.getUuid())), true);

        discoveryFinishedEventHandler
                .handleEvent(DiscoveryFinishedEventHandler
                        .constructEventMessage(discovery.getUuid(), userUuid, null,
                                new DiscoveryResult(DiscoveryStatus.COMPLETED, "Test")));
        discovery = discoveryRepository.findByUuid(discovery.getUuid()).orElseThrow();
        Assertions.assertEquals(DiscoveryStatus.IN_PROGRESS, discovery.getStatus());

        discoveryFinishedEventHandler
                .handleEvent(DiscoveryFinishedEventHandler
                        .constructEventMessage(discovery.getUuid(), null, null,
                                new DiscoveryResult(DiscoveryStatus.PROCESSING, "Test finalize")));
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
    }

    private void mockAuthResponse(NameAndUuidDto userInfo) {
        AuthServiceWireMockStubs.stubImpersonation(mockServer, UUID.fromString(userInfo.getUuid()), userInfo.getName());
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

        Assertions
                .assertDoesNotThrow(() -> scheduledJobFinishedEventHandler
                        .handleEvent(ScheduledJobFinishedEventHandler
                                .constructEventMessage(scheduledJob.getUuid(),
                                        new ScheduledTaskResult(SchedulerJobExecutionStatus.SUCCESS, "Test"))));

        ScheduledJobFinishedEventData eventData = new ScheduledJobFinishedEventData();
        eventData.setJobName(scheduledJob.getJobName());
        eventData.setJobType(scheduledJob.getJobType());
        eventData.setStatus(SchedulerJobExecutionStatus.SUCCESS.getLabel());
        NotificationMessage notificationMessage = new NotificationMessage(ResourceEvent.SCHEDULED_JOB_FINISHED,
                Resource.SCHEDULED_JOB, scheduledJob.getUuid(), null,
                NotificationRecipient.buildUserNotificationRecipient(UUID.randomUUID()), eventData);
        Assertions.assertDoesNotThrow(() -> notificationListener.processMessage(notificationMessage));
    }

    @Test
    void testCertificateUploadedEventCertificateIgnored() throws Exception {
        X509Certificate certificate = CertificateGeneratorHelper.generateCACertificate(null, "CN=test");
        String fingerprint = CertificateUtil.getThumbprint(certificate);
        final CertificateUploadEventMessageData eventMessageData = CertificateUploadEventMessageData
                .builder()
                .certificateContent(Base64.getEncoder().encodeToString(certificate.getEncoded()))
                .build();

        createCertificateTriggerAssociation(ResourceEvent.CERTIFICATE_UPLOADED, null, null, true);
        Assertions
                .assertDoesNotThrow(() -> certificateUploadedEventHandler
                        .handleEvent(CertificateUploadedEventHandler.constructEventMessage(eventMessageData)));
        Assertions.assertFalse(certificateRepository.findByFingerprint(fingerprint).isPresent());

        List<TriggerHistory> histories = triggerHistoryRepository.findAll();
        Assertions.assertEquals(1, histories.size());
        TriggerHistory th = histories.getFirst();
        Assertions.assertTrue(th.isConditionsMatched());
        Assertions.assertTrue(th.isActionsPerformed());

        Assertions.assertNotNull(th.getMessage());
        Assertions
                .assertTrue(th.getMessage().contains(fingerprint),
                        "ignore TriggerHistory.message includes the fingerprint");
    }

    @Test
    void testCertificateUploadedEventCertificateMalformedContent() {
        final CertificateUploadEventMessageData eventMessageData = CertificateUploadEventMessageData
                .builder()
                .certificateContent("invalid")
                .build();

        Assertions
                .assertDoesNotThrow(() -> certificateUploadedEventHandler
                        .handleEvent(CertificateUploadedEventHandler.constructEventMessage(eventMessageData)));
        EventHistory eventHistory = eventHistoryRepository.findAll().stream().findFirst().orElseThrow();
        Assertions.assertEquals(EventStatus.FAILED, eventHistory.getStatus());
    }

    @Test
    void testCertificateUploadedEventCertificateDuplicateFingerprint() throws Exception {
        X509Certificate certificate = CertificateGeneratorHelper.generateCACertificate(null, "CN=test");
        final CertificateUploadEventMessageData eventMessageData = CertificateUploadEventMessageData
                .builder()
                .certificateContent(Base64.getEncoder().encodeToString(certificate.getEncoded()))
                .build();

        UploadCertificateRequestDto uploadCertificateRequestDto = new UploadCertificateRequestDto();
        uploadCertificateRequestDto.setCertificate(Base64.getEncoder().encodeToString(certificate.getEncoded()));
        certificateService.uploadSync(uploadCertificateRequestDto);

        // Test duplicate fingerprint
        Assertions
                .assertDoesNotThrow(() -> certificateUploadedEventHandler
                        .handleEvent(CertificateUploadedEventHandler.constructEventMessage(eventMessageData)));
        // The first history is for the created certificate, so we need to check the second one
        EventHistory eventHistory = eventHistoryRepository.findAll().getLast();
        Assertions.assertEquals(EventStatus.FAILED, eventHistory.getStatus());
    }

    @Test
    void testCertificateUploadedEvent() throws Exception {
        X509Certificate certificate = CertificateGeneratorHelper.generateCACertificate(null, "CN=test");
        String fingerprint = CertificateUtil.getThumbprint(certificate);
        final CertificateUploadEventMessageData eventMessageData = CertificateUploadEventMessageData
                .builder()
                .certificateContent(Base64.getEncoder().encodeToString(certificate.getEncoded()))
                .build();

        // Test without any triggers in settings
        Assertions
                .assertDoesNotThrow(() -> certificateUploadedEventHandler
                        .handleEvent(CertificateUploadedEventHandler.constructEventMessage(eventMessageData)));

        Certificate uploadedCertificate = certificateRepository.findByFingerprint(fingerprint).orElseThrow();
        Assertions.assertEquals(certificate.getSubjectX500Principal().getName(), uploadedCertificate.getSubjectDn());
        Assertions.assertNotNull(uploadedCertificate.getCertificateContent());
        Assertions.assertNotNull(uploadedCertificate.getKey());

        // Test setting actions
        certificateService.deleteCertificate(uploadedCertificate.getSecuredUuid());

        // Creates a trigger that sets custom attribute value to "important"
        createCertificateTriggerAssociation(ResourceEvent.CERTIFICATE_UPLOADED, null, null, false);
        Assertions
                .assertDoesNotThrow(() -> certificateUploadedEventHandler
                        .handleEvent(CertificateUploadedEventHandler.constructEventMessage(eventMessageData)));
        uploadedCertificate = certificateRepository.findByFingerprint(fingerprint).orElseThrow();
        CertificateDetailDto certificateDetailDto = certificateService
                .getCertificate(uploadedCertificate.getSecuredUuid());
        Assertions.assertFalse(certificateDetailDto.getCustomAttributes().isEmpty());

        // Test setting actions with custom attributes in the request and user UUID, and that it overrides the value
        // from the trigger execution
        RequestAttributeV3 requestAttributeV3 = new RequestAttributeV3();
        requestAttributeV3.setUuid(UUID.fromString(CERTIFICATE_CUSTOM_ATTRIBUTE_UUID));
        requestAttributeV3.setName(CERTIFICATE_CUSTOM_ATTRIBUTE_NAME);
        requestAttributeV3.setContentType(AttributeContentType.STRING);
        requestAttributeV3.setContent(List.of(new StringAttributeContentV3("fromRequest")));
        CertificateUploadEventMessageData eventMessageData2 = CertificateUploadEventMessageData
                .builder()
                .certificateContent(Base64.getEncoder().encodeToString(certificate.getEncoded()))
                .customAttributes(List.of(requestAttributeV3))
                .build();

        certificateService.deleteCertificate(uploadedCertificate.getSecuredUuid());
        Assertions
                .assertDoesNotThrow(() -> certificateUploadedEventHandler
                        .handleEvent(CertificateUploadedEventHandler.constructEventMessage(eventMessageData2)));
        uploadedCertificate = certificateRepository.findByFingerprint(fingerprint).orElseThrow();
        certificateDetailDto = certificateService.getCertificate(uploadedCertificate.getSecuredUuid());
        Assertions.assertFalse(certificateDetailDto.getCustomAttributes().isEmpty());
        Optional<ResponseAttribute> customAttributeDtoOptional = certificateDetailDto
                .getCustomAttributes()
                .stream()
                .filter(attr -> CERTIFICATE_CUSTOM_ATTRIBUTE_NAME.equals(attr.getName()))
                .findFirst();
        Assertions.assertTrue(customAttributeDtoOptional.isPresent());
        Assertions
                .assertEquals("fromRequest",
                        ((List<StringAttributeContentV3>) customAttributeDtoOptional.get().getContent())
                                .getFirst()
                                .getData());
    }

    @Test
    void testEventDataNotifications() throws NotFoundException, AlreadyExistException {
        Group group = new Group();
        group.setName("TestGroup");
        group.setEmail("grouptest@example.com");
        group = groupRepository.save(group);

        mockServer = new WireMockServer(WireMockPorts.AUTH_SERVICE);
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
        EventData eventData = EventDataBuilder
                .getCertificateStatusChangedEventData(certificate,
                        new CertificateValidationStatus[]{
                                CertificateValidationStatus.INACTIVE,
                                CertificateValidationStatus.VALID});
        final NotificationMessage messageCertificateStatusChanged = new NotificationMessage(
                ResourceEvent.CERTIFICATE_STATUS_CHANGED, Resource.CERTIFICATE, certificate.getUuid(),
                notificationProfileUuids, null, eventData);
        Assertions.assertDoesNotThrow(() -> notificationListener.processMessage(messageCertificateStatusChanged));
        Assertions.assertDoesNotThrow(() -> notificationListener.processMessage(messageCertificateStatusChanged));
        PendingNotification pendingNotification = pendingNotificationRepository
                .findByNotificationProfileUuidAndResourceAndObjectUuidAndEvent(notificationProfileUuids.getLast(),
                        Resource.CERTIFICATE, certificate.getUuid(), ResourceEvent.CERTIFICATE_STATUS_CHANGED);
        Assertions.assertNull(pendingNotification);

        eventData = EventDataBuilder.getCertificateActionPerformedEventData(certificate, ResourceAction.REVOKE);
        final NotificationMessage messageCertificateActionPerformed = new NotificationMessage(
                ResourceEvent.CERTIFICATE_ACTION_PERFORMED, Resource.CERTIFICATE, certificate.getUuid(),
                notificationProfileUuids, null, eventData);
        Assertions.assertDoesNotThrow(() -> notificationListener.processMessage(messageCertificateActionPerformed));

        Discovery discovery = new Discovery();
        discovery.setName("TestDiscovery");
        discovery.setStatus(DiscoveryStatus.COMPLETED);
        discovery.setConnectorStatus(DiscoveryStatus.COMPLETED);
        discovery.setConnectorUuid(UUID.randomUUID());
        discovery.setConnectorName("TestDiscoveryConnector");
        discoveryRepository.save(discovery);

        eventData = EventDataBuilder.getCertificateDiscoveredEventData(certificate, discovery, ownerUuid);
        final NotificationMessage messageCertificateDiscovered = new NotificationMessage(
                ResourceEvent.CERTIFICATE_DISCOVERED, Resource.CERTIFICATE, certificate.getUuid(),
                notificationProfileUuids, null, eventData);
        Assertions.assertDoesNotThrow(() -> notificationListener.processMessage(messageCertificateDiscovered));

        // discovery events
        eventData = EventDataBuilder.getDiscoveryFinishedEventData(discovery);
        final NotificationMessage messageDiscoveryFinished = new NotificationMessage(ResourceEvent.DISCOVERY_FINISHED,
                Resource.DISCOVERY, discovery.getUuid(), notificationProfileUuids, null, eventData);
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

        ApprovalStepDto approvalStepDto = approvalProfile
                .getTheLatestApprovalProfileVersion()
                .getApprovalSteps()
                .getFirst()
                .mapToDto();
        eventData = EventDataBuilder
                .getApprovalRequestedEventData(approval, approvalProfile, approvalStepDto, "TestUser1");
        final NotificationMessage messageApprovalRequested = new NotificationMessage(ResourceEvent.APPROVAL_REQUESTED,
                Resource.APPROVAL, approval.getUuid(), notificationProfileUuids, null, eventData);
        Assertions.assertDoesNotThrow(() -> notificationListener.processMessage(messageApprovalRequested));

        eventData = EventDataBuilder.getApprovalEventData(approval, approvalProfile, "TestUser1");
        final NotificationMessage messageApprovalClosed = new NotificationMessage(ResourceEvent.APPROVAL_CLOSED,
                Resource.APPROVAL, approval.getUuid(), notificationProfileUuids, null, eventData);
        Assertions.assertDoesNotThrow(() -> notificationListener.processMessage(messageApprovalClosed));

        eventData = EventDataBuilder.getCertificateExpiringEventData(certificate);
        final NotificationMessage messageCertificateExpiring = new NotificationMessage(
                ResourceEvent.CERTIFICATE_EXPIRING, Resource.CERTIFICATE, certificate.getUuid(),
                notificationProfileUuids, null, eventData);
        Assertions.assertDoesNotThrow(() -> notificationListener.processMessage(messageCertificateExpiring));
        Assertions.assertDoesNotThrow(() -> notificationListener.processMessage(messageCertificateExpiring));
        pendingNotification = pendingNotificationRepository
                .findByNotificationProfileUuidAndResourceAndObjectUuidAndEvent(notificationProfileUuids.getLast(),
                        Resource.CERTIFICATE, certificate.getUuid(), ResourceEvent.CERTIFICATE_EXPIRING);
        Assertions.assertNotNull(pendingNotification);
        Assertions.assertEquals(1, pendingNotification.getRepetitions(), "Second notification should be suppressed");
    }

    private List<UUID> prepareDataAndMockServer(WireMockServer mockServer, Group group, UUID ownerUuid, UUID roleUuid)
            throws NotFoundException, AlreadyExistException {
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

        mockServer
                .stubFor(WireMock
                        .get(WireMock.urlPathMatching("/v1/notificationProvider/[^/]+/attributes/mapping"))
                        .willReturn(WireMock.okJson("[]")));
        mockServer
                .stubFor(WireMock
                        .post(WireMock.urlPathMatching("/v1/notificationProvider/notifications/[^/]+/notify"))
                        .willReturn(WireMock.ok()));
        mockServer.stubFor(WireMock.get(WireMock.urlPathMatching("/auth/roles/[^/]+")).willReturn(WireMock.okJson("""
                {
                    "uuid": "%s",
                    "name": "TestRole",
                    "email": "testrole@example.com",
                    "systemRole": false
                },
                """.formatted(roleUuid.toString()))));
        mockServer.stubFor(WireMock.get(WireMock.urlPathMatching("/auth/users")).willReturn(WireMock.okJson("""
                {
                    "data": %s
                }
                """.formatted(userListResponse))));
        mockServer
                .stubFor(WireMock
                        .get(WireMock.urlPathMatching("/auth/users/[^/]+"))
                        .willReturn(WireMock.okJson(ownerUserResponse)));
        mockServer
                .stubFor(WireMock
                        .get(WireMock.urlPathMatching("/auth/roles/[^/]+/users"))
                        .willReturn(WireMock.okJson(userListResponse)));

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
        NotificationProfileDetailDto notificationProfileDetailDto = notificationProfileService
                .createNotificationProfile(requestDto);

        requestDto.setName("TestProfileRole");
        requestDto.setRecipientType(RecipientType.ROLE);
        requestDto.setRecipientUuids(List.of(roleUuid));
        NotificationProfileDetailDto notificationProfileDetailDto2 = notificationProfileService
                .createNotificationProfile(requestDto);

        requestDto.setName("TestProfileUser");
        requestDto.setRecipientType(RecipientType.USER);
        requestDto.setRecipientUuids(List.of(ownerUuid));
        NotificationProfileDetailDto notificationProfileDetailDto3 = notificationProfileService
                .createNotificationProfile(requestDto);

        requestDto.setName("TestProfileOwner");
        requestDto.setRecipientType(RecipientType.OWNER);
        requestDto.setRecipientUuids(null);
        NotificationProfileDetailDto notificationProfileDetailDto4 = notificationProfileService
                .createNotificationProfile(requestDto);

        requestDto.setName("TestProfileGroup");
        requestDto.setRepetitions(1);
        requestDto.setRecipientType(RecipientType.GROUP);
        requestDto.setRecipientUuids(List.of(group.getUuid()));
        NotificationProfileDetailDto notificationProfileDetailDto5 = notificationProfileService
                .createNotificationProfile(requestDto);

        return List
                .of(UUID.fromString(notificationProfileDetailDto.getUuid()),
                        UUID.fromString(notificationProfileDetailDto2.getUuid()),
                        UUID.fromString(notificationProfileDetailDto3.getUuid()),
                        UUID.fromString(notificationProfileDetailDto4.getUuid()),
                        UUID.fromString(notificationProfileDetailDto5.getUuid()));

    }
}
