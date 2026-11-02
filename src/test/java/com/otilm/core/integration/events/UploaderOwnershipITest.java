package com.otilm.core.integration.events;

import ch.qos.logback.classic.Logger;
import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.core.read.ListAppender;
import com.github.tomakehurst.wiremock.WireMockServer;
import com.github.tomakehurst.wiremock.client.WireMock;
import com.otilm.api.model.common.NameAndUuidDto;
import com.otilm.api.model.core.auth.Resource;
import com.otilm.api.model.core.certificate.CertificateEvent;
import com.otilm.api.model.core.certificate.CertificateState;
import com.otilm.api.model.core.other.ResourceEvent;
import com.otilm.api.model.core.search.FilterConditionOperator;
import com.otilm.api.model.core.search.FilterFieldSource;
import com.otilm.api.model.core.settings.CertificateSettingsUpdateDto;
import com.otilm.api.model.core.settings.CertificateUploadSettingsUpdateDto;
import com.otilm.api.model.core.settings.PlatformSettingsUpdateDto;
import com.otilm.api.model.core.workflows.ActionRequestDto;
import com.otilm.api.model.core.workflows.ConditionItemRequestDto;
import com.otilm.api.model.core.workflows.ConditionRequestDto;
import com.otilm.api.model.core.workflows.ConditionType;
import com.otilm.api.model.core.workflows.ExecutionItemRequestDto;
import com.otilm.api.model.core.workflows.ExecutionRequestDto;
import com.otilm.api.model.core.workflows.ExecutionType;
import com.otilm.api.model.core.workflows.RuleRequestDto;
import com.otilm.api.model.core.workflows.TriggerRequestDto;
import com.otilm.api.model.core.workflows.TriggerType;
import com.otilm.core.dao.entity.Certificate;
import com.otilm.core.dao.entity.CertificateEventHistory;
import com.otilm.core.dao.repository.CertificateEventHistoryRepository;
import com.otilm.core.dao.repository.CertificateRepository;
import com.otilm.core.enums.FilterField;
import com.otilm.core.events.handlers.CertificateUploadedEventHandler;
import com.otilm.core.events.transaction.UploaderOwnershipEvent;
import com.otilm.core.helpers.CertificateGeneratorHelper;
import com.otilm.core.messaging.jms.listeners.EventListener;
import com.otilm.core.messaging.model.CertificateUploadEventMessageData;
import com.otilm.core.messaging.model.EventMessage;
import com.otilm.core.model.auth.ResourceAction;
import com.otilm.core.service.ActionExternalService;
import com.otilm.core.service.CertificateExternalService;
import com.otilm.core.service.ResourceObjectAssociationService;
import com.otilm.core.service.RuleExternalService;
import com.otilm.core.service.SettingExternalService;
import com.otilm.core.service.TriggerExternalService;
import com.otilm.core.service.handler.UploaderOwnershipListener;
import com.otilm.core.util.AuthHelper;
import com.otilm.core.util.AuthServiceWireMockStubs;
import com.otilm.core.util.BaseSpringBootTest;
import com.otilm.core.util.CertificateUtil;
import com.otilm.core.util.WireMockPorts;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.UUID;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authorization.AuthorizationDeniedException;
import org.springframework.security.core.context.SecurityContextHolder;

class UploaderOwnershipITest extends BaseSpringBootTest {

    @Autowired
    private CertificateUploadedEventHandler certificateUploadedEventHandler;
    @Autowired
    private SettingExternalService settingService;
    @Autowired
    private CertificateRepository certificateRepository;
    @Autowired
    private CertificateEventHistoryRepository certificateEventHistoryRepository;
    @Autowired
    private ResourceObjectAssociationService associationService;
    @Autowired
    private UploaderOwnershipListener uploaderOwnershipListener;
    @Autowired
    private EventListener eventListener;
    @Autowired
    private CertificateExternalService certificateService;
    @Autowired
    private RuleExternalService ruleService;
    @Autowired
    private ActionExternalService actionService;
    @Autowired
    private TriggerExternalService triggerService;

    private WireMockServer mockServer;

    @AfterEach
    void tearDown() {
        if (mockServer != null) {
            mockServer.stop();
        }
    }

    @Test
    void uploaderIsNotMadeOwnerByDefault() throws Exception {
        Certificate uploaded = upload();

        Assertions.assertNull(associationService.getOwner(Resource.CERTIFICATE, uploaded.getUuid()));
    }

    @Test
    void uploaderBecomesOwnerWhenEnabled() throws Exception {
        enableAutomaticOwnership(true);
        NameAndUuidDto uploader = AuthHelper.getUserIdentification();

        Certificate uploaded = upload();

        NameAndUuidDto owner = associationService.getOwner(Resource.CERTIFICATE, uploaded.getUuid());
        Assertions.assertNotNull(owner);
        Assertions.assertEquals(uploader.getUuid(), owner.getUuid());
        Assertions.assertEquals(uploader.getName(), owner.getName());
        Assertions.assertEquals(List.of("undefined -> " + uploader.getName()), ownerChanges(uploaded));
    }

    @Test
    void uploaderIsNotMadeOwnerAfterTurningTheSettingOff() throws Exception {
        enableAutomaticOwnership(true);
        enableAutomaticOwnership(false);

        Certificate uploaded = upload();

        Assertions.assertNull(associationService.getOwner(Resource.CERTIFICATE, uploaded.getUuid()));
    }

    @Test
    void ownerSetByTriggerIsKept() throws Exception {
        enableAutomaticOwnership(true);
        UUID triggerOwnerUuid = UUID.randomUUID();
        String triggerOwnerName = "team-account";
        seedSetOwnerTrigger(triggerOwnerUuid, triggerOwnerName);

        Certificate uploaded = upload();

        NameAndUuidDto owner = associationService.getOwner(Resource.CERTIFICATE, uploaded.getUuid());
        Assertions.assertNotNull(owner);
        Assertions.assertEquals(triggerOwnerUuid.toString(), owner.getUuid());
        Assertions.assertEquals(List.of("undefined -> " + triggerOwnerName), ownerChanges(uploaded));
    }

    @Test
    void failureToStoreTheOwnerIsLoggedAndLeavesTheCertificate() throws Exception {
        Certificate uploaded = upload();
        Logger listenerLogger = (Logger) LoggerFactory.getLogger(UploaderOwnershipListener.class);
        ListAppender<ILoggingEvent> appender = new ListAppender<>();
        appender.start();
        listenerLogger.addAppender(appender);

        try {
            // a username longer than the owner column takes, so storing the owner fails in the database
            Assertions
                    .assertDoesNotThrow(() -> uploaderOwnershipListener
                            .handleUploaderOwnership(new UploaderOwnershipEvent(uploaded.getUuid(), UUID.randomUUID(),
                                    "u".repeat(300))));
        } finally {
            listenerLogger.detachAppender(appender);
        }

        Assertions.assertNull(associationService.getOwner(Resource.CERTIFICATE, uploaded.getUuid()));
        Assertions.assertTrue(certificateRepository.findByUuid(uploaded.getUuid()).isPresent());
        Assertions
                .assertTrue(
                        appender.list
                                .stream()
                                .anyMatch(event -> event.getFormattedMessage().contains("Unable to make")),
                        "the failure is logged");
    }

    @Test
    void uploaderIsNotMadeOwnerWhenATriggerClearsTheOwner() throws Exception {
        enableAutomaticOwnership(true);
        seedSetOwnerTrigger(null, null);

        Certificate uploaded = upload();

        Assertions.assertNull(associationService.getOwner(Resource.CERTIFICATE, uploaded.getUuid()));
        Assertions.assertEquals(List.of(), ownerChanges(uploaded));
    }

    @Test
    void uploaderIsNotMadeOwnerWhenATriggerClearsTheOwnerAndAnotherOfItsExecutionsFails() throws Exception {
        enableAutomaticOwnership(true);
        seedSetOwnerTrigger(null, null, FailingPart.OTHER_EXECUTION);

        Certificate uploaded = upload();

        Assertions.assertNull(associationService.getOwner(Resource.CERTIFICATE, uploaded.getUuid()));
        Assertions.assertEquals(List.of(), ownerChanges(uploaded));
    }

    @Test
    void uploaderIsNotMadeOwnerWhenATriggerClearsTheOwnerAndAnotherItemOfTheSameExecutionFails() throws Exception {
        enableAutomaticOwnership(true);
        seedSetOwnerTrigger(null, null, FailingPart.SAME_EXECUTION);

        Certificate uploaded = upload();

        Assertions.assertNull(associationService.getOwner(Resource.CERTIFICATE, uploaded.getUuid()));
        Assertions.assertEquals(List.of(), ownerChanges(uploaded));
    }

    @Test
    void warnsWhenTheUploaderIsNotKnown() throws Exception {
        enableAutomaticOwnership(true);
        Logger handlerLogger = (Logger) LoggerFactory.getLogger(CertificateUploadedEventHandler.class);
        ListAppender<ILoggingEvent> appender = new ListAppender<>();
        appender.start();
        handlerLogger.addAppender(appender);
        SecurityContextHolder.clearContext();

        Certificate uploaded;
        try {
            uploaded = upload();
        } finally {
            handlerLogger.detachAppender(appender);
        }

        Assertions.assertNull(associationService.getOwner(Resource.CERTIFICATE, uploaded.getUuid()));
        Assertions
                .assertTrue(
                        appender.list
                                .stream()
                                .anyMatch(event -> event.getFormattedMessage().contains("uploader of certificate")),
                        "the missing owner is logged");
    }

    @Test
    void uploaderCarriedInTheMessageBecomesOwnerWhenProcessedWithoutASecurityContext() throws Exception {
        enableAutomaticOwnership(true);
        UUID uploaderUuid = UUID.fromString(AuthHelper.getUserIdentification().getUuid());
        X509Certificate x509 = CertificateGeneratorHelper.generateCACertificate(null, "CN=queued");
        EventMessage message = CertificateUploadedEventHandler
                .constructEventMessage(CertificateUploadEventMessageData
                        .builder()
                        .certificateContent(Base64.getEncoder().encodeToString(x509.getEncoded()))
                        .build());
        mockServer = new WireMockServer(WireMockPorts.AUTH_SERVICE);
        mockServer.start();
        WireMock.configureFor("localhost", mockServer.port());
        AuthServiceWireMockStubs.stubImpersonation(mockServer, uploaderUuid, "queued-uploader");
        // the queue consumer thread has no identity of its own
        SecurityContextHolder.clearContext();

        eventListener.processMessage(message);
        SecurityContextHolder.clearContext();

        Certificate uploaded = certificateRepository
                .findByFingerprint(CertificateUtil.getThumbprint(x509))
                .orElseThrow();
        NameAndUuidDto owner = associationService.getOwner(Resource.CERTIFICATE, uploaded.getUuid());
        Assertions.assertNotNull(owner);
        Assertions.assertEquals(uploaderUuid.toString(), owner.getUuid());
        Assertions.assertEquals("queued-uploader", owner.getName());
    }

    @Test
    void ownerOpensTheUploadedCertificateWithoutThePermissionToSeeCertificates() throws Exception {
        enableAutomaticOwnership(true);
        Certificate owned = upload();
        enableAutomaticOwnership(false);
        Certificate notOwned = upload("CN=someone-elses");
        denyResourceAccess(Resource.CERTIFICATE, ResourceAction.DETAIL);

        Assertions.assertDoesNotThrow(() -> certificateService.getCertificate(owned.getSecuredUuid()));
        Assertions
                .assertThrows(AuthorizationDeniedException.class,
                        () -> certificateService.getCertificate(notOwned.getSecuredUuid()));
    }

    private Certificate upload() throws Exception {
        return upload("CN=uploaded");
    }

    private Certificate upload(String subject) throws Exception {
        X509Certificate x509 = CertificateGeneratorHelper.generateCACertificate(null, subject);
        String fingerprint = CertificateUtil.getThumbprint(x509);
        CertificateUploadEventMessageData data = CertificateUploadEventMessageData
                .builder()
                .certificateContent(Base64.getEncoder().encodeToString(x509.getEncoded()))
                .build();

        certificateUploadedEventHandler.handleEvent(CertificateUploadedEventHandler.constructEventMessage(data));

        return certificateRepository.findByFingerprint(fingerprint).orElseThrow();
    }

    private void enableAutomaticOwnership(boolean enabled) {
        CertificateUploadSettingsUpdateDto upload = new CertificateUploadSettingsUpdateDto();
        upload.setAutomaticOwnership(enabled);
        CertificateSettingsUpdateDto certificates = new CertificateSettingsUpdateDto();
        certificates.setUpload(upload);
        PlatformSettingsUpdateDto update = new PlatformSettingsUpdateDto();
        update.setCertificates(certificates);
        settingService.updatePlatformSettings(update);
    }

    private List<String> ownerChanges(Certificate certificate) {
        return certificateEventHistoryRepository
                .findByCertificateOrderByCreatedDesc(certificate)
                .stream()
                .filter(history -> history.getEvent() == CertificateEvent.UPDATE_OWNER)
                .map(CertificateEventHistory::getMessage)
                .toList();
    }

    private void seedSetOwnerTrigger(UUID ownerUuid, String ownerName) throws Exception {
        seedSetOwnerTrigger(ownerUuid, ownerName, FailingPart.NONE);
    }

    private void seedSetOwnerTrigger(UUID ownerUuid, String ownerName, FailingPart failingPart) throws Exception {
        mockServer = new WireMockServer(WireMockPorts.AUTH_SERVICE);
        mockServer.start();
        WireMock.configureFor("localhost", mockServer.port());
        AuthServiceWireMockStubs
                .stubImpersonation(mockServer, ownerUuid == null ? UUID.randomUUID() : ownerUuid,
                        ownerName == null ? "unused" : ownerName);

        ConditionItemRequestDto conditionItem = new ConditionItemRequestDto();
        conditionItem.setFieldSource(FilterFieldSource.PROPERTY);
        conditionItem.setFieldIdentifier(FilterField.CERTIFICATE_STATE.name());
        conditionItem.setOperator(FilterConditionOperator.EQUALS);
        conditionItem.setValue(List.of(CertificateState.ISSUED.getCode()));
        ConditionRequestDto conditionRequest = new ConditionRequestDto();
        conditionRequest.setName("UploadedCertificateCondition");
        conditionRequest.setResource(Resource.CERTIFICATE);
        conditionRequest.setType(ConditionType.CHECK_FIELD);
        conditionRequest.setItems(List.of(conditionItem));
        String conditionUuid = ruleService.createCondition(conditionRequest).getUuid();

        RuleRequestDto ruleRequest = new RuleRequestDto();
        ruleRequest.setName("UploadedCertificateRule");
        ruleRequest.setResource(Resource.CERTIFICATE);
        ruleRequest.setConditionsUuids(List.of(conditionUuid));
        String ruleUuid = ruleService.createRule(ruleRequest).getUuid();

        ExecutionItemRequestDto executionItem = new ExecutionItemRequestDto();
        executionItem.setFieldSource(FilterFieldSource.PROPERTY);
        executionItem.setFieldIdentifier(FilterField.OWNER.toString());
        executionItem.setData(ownerUuid == null ? null : ownerUuid.toString());
        ExecutionRequestDto executionRequest = new ExecutionRequestDto();
        executionRequest.setName("SetUploadOwnerExecution");
        executionRequest.setResource(Resource.CERTIFICATE);
        executionRequest.setType(ExecutionType.SET_FIELD);
        if (failingPart == FailingPart.SAME_EXECUTION) {
            ExecutionItemRequestDto failingItem = new ExecutionItemRequestDto();
            failingItem.setFieldSource(FilterFieldSource.PROPERTY);
            failingItem.setFieldIdentifier(FilterField.GROUP_NAME.toString());
            failingItem.setData("not-a-uuid");
            executionRequest.setItems(List.of(executionItem, failingItem));
        } else {
            executionRequest.setItems(List.of(executionItem));
        }
        String executionUuid = actionService.createExecution(executionRequest).getUuid();

        List<String> executionUuids = new ArrayList<>(List.of(executionUuid));
        if (failingPart == FailingPart.OTHER_EXECUTION) {
            // a group that is not a UUID, which the evaluator refuses
            ExecutionItemRequestDto failingItem = new ExecutionItemRequestDto();
            failingItem.setFieldSource(FilterFieldSource.PROPERTY);
            failingItem.setFieldIdentifier(FilterField.GROUP_NAME.toString());
            failingItem.setData("not-a-uuid");
            ExecutionRequestDto failingRequest = new ExecutionRequestDto();
            failingRequest.setName("FailingUploadExecution");
            failingRequest.setResource(Resource.CERTIFICATE);
            failingRequest.setType(ExecutionType.SET_FIELD);
            failingRequest.setItems(List.of(failingItem));
            executionUuids.add(actionService.createExecution(failingRequest).getUuid());
        }

        ActionRequestDto actionRequest = new ActionRequestDto();
        actionRequest.setName("SetUploadOwnerAction");
        actionRequest.setResource(Resource.CERTIFICATE);
        actionRequest.setExecutionsUuids(executionUuids);
        String actionUuid = actionService.createAction(actionRequest).getUuid();

        TriggerRequestDto triggerRequest = new TriggerRequestDto();
        triggerRequest.setName("SetUploadOwnerTrigger");
        triggerRequest.setType(TriggerType.EVENT);
        triggerRequest.setEvent(ResourceEvent.CERTIFICATE_UPLOADED);
        triggerRequest.setResource(Resource.CERTIFICATE);
        triggerRequest.setRulesUuids(List.of(ruleUuid));
        triggerRequest.setActionsUuids(List.of(actionUuid));
        triggerRequest.setIgnoreTrigger(false);
        String triggerUuid = triggerService.createTrigger(triggerRequest).getUuid();

        triggerService
                .createTriggerAssociations(ResourceEvent.CERTIFICATE_UPLOADED, null, null,
                        List.of(UUID.fromString(triggerUuid)), true);
    }

    private enum FailingPart {
        NONE,
        OTHER_EXECUTION,
        SAME_EXECUTION
    }
}
