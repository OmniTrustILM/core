package com.otilm.core.integration.events;

import ch.qos.logback.classic.Logger;
import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.core.read.ListAppender;
import com.github.tomakehurst.wiremock.WireMockServer;
import com.github.tomakehurst.wiremock.client.WireMock;
import com.otilm.api.model.common.NameAndUuidDto;
import com.otilm.api.model.core.auth.Resource;
import com.otilm.api.model.core.certificate.CertificateDetailDto;
import com.otilm.api.model.core.certificate.CertificateEvent;
import com.otilm.api.model.core.settings.CertificateSettingsUpdateDto;
import com.otilm.api.model.core.settings.CertificateUploadSettingsUpdateDto;
import com.otilm.api.model.core.settings.PlatformSettingsUpdateDto;
import com.otilm.core.dao.entity.Certificate;
import com.otilm.core.dao.entity.CertificateEventHistory;
import com.otilm.core.dao.repository.CertificateEventHistoryRepository;
import com.otilm.core.dao.repository.CertificateRepository;
import com.otilm.core.events.handlers.CertificateUploadedEventHandler;
import com.otilm.core.events.transaction.UploaderOwnershipEvent;
import com.otilm.core.helpers.CertificateGeneratorHelper;
import com.otilm.core.messaging.jms.listeners.EventListener;
import com.otilm.core.messaging.model.CertificateUploadEventMessageData;
import com.otilm.core.messaging.model.EventMessage;
import com.otilm.core.model.auth.ResourceAction;
import com.otilm.core.service.CertificateExternalService;
import com.otilm.core.service.ResourceObjectAssociationService;
import com.otilm.core.service.SettingExternalService;
import com.otilm.core.service.handler.UploaderOwnershipListener;
import com.otilm.core.util.AuthHelper;
import com.otilm.core.util.AuthServiceWireMockStubs;
import com.otilm.core.util.BaseSpringBootTest;
import com.otilm.core.util.CertificateUtil;
import com.otilm.core.util.WireMockPorts;
import com.otilm.core.util.seeders.CertificateUploadTriggerSeeder;
import java.security.cert.X509Certificate;
import java.util.Base64;
import java.util.List;
import java.util.UUID;
import org.assertj.core.api.ThrowableAssert.ThrowingCallable;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authorization.AuthorizationDeniedException;
import org.springframework.security.core.context.SecurityContextHolder;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class UploaderOwnershipITest extends BaseSpringBootTest {

    private static final String UPLOADED_SUBJECT = "CN=uploaded";

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
    private CertificateUploadTriggerSeeder triggerSeeder;

    private WireMockServer authService;
    private Logger capturedLogger;
    private ListAppender<ILoggingEvent> capturedLogs;

    @AfterEach
    void tearDown() {
        if (authService != null) {
            authService.stop();
        }
        if (capturedLogger != null) {
            capturedLogger.detachAppender(capturedLogs);
        }
    }

    @Test
    void leavesCertificateWithoutOwner_whenAutomaticOwnershipIsOff() throws Exception {
        // given — automatic ownership was never turned on

        // when
        Certificate uploaded = upload(UPLOADED_SUBJECT);

        // then
        assertThat(ownerOf(uploaded)).isNull();
    }

    @Test
    void makesUploaderOwner_whenAutomaticOwnershipIsOn() throws Exception {
        // given
        enableAutomaticOwnership(true);
        NameAndUuidDto uploader = AuthHelper.getUserIdentification();

        // when
        Certificate uploaded = upload(UPLOADED_SUBJECT);

        // then
        assertThat(ownerOf(uploaded))
                .extracting(NameAndUuidDto::getUuid, NameAndUuidDto::getName)
                .containsExactly(uploader.getUuid(), uploader.getName());
        assertThat(ownerChanges(uploaded)).containsExactly("undefined -> " + uploader.getName());
    }

    @Test
    void leavesCertificateWithoutOwner_whenAutomaticOwnershipWasTurnedOff() throws Exception {
        // given
        enableAutomaticOwnership(true);
        enableAutomaticOwnership(false);

        // when
        Certificate uploaded = upload(UPLOADED_SUBJECT);

        // then
        assertThat(ownerOf(uploaded)).isNull();
    }

    @Test
    void keepsTriggerOwner_whenTriggerSetsOwner() throws Exception {
        // given
        enableAutomaticOwnership(true);
        var teamAccountUuid = UUID.randomUUID();
        var teamAccountName = "team-account";
        startAuthService(teamAccountUuid, teamAccountName);
        triggerSeeder.seedSetOwnerTrigger(teamAccountUuid);

        // when
        Certificate uploaded = upload(UPLOADED_SUBJECT);

        // then
        assertThat(ownerOf(uploaded).getUuid()).isEqualTo(teamAccountUuid.toString());
        assertThat(ownerChanges(uploaded)).containsExactly("undefined -> " + teamAccountName);
    }

    @Test
    void leavesCertificateWithoutOwner_whenTriggerClearsOwner() throws Exception {
        // given
        enableAutomaticOwnership(true);
        startAuthService(UUID.randomUUID(), "trigger-owner");
        triggerSeeder.seedClearOwnerTrigger();

        // when
        Certificate uploaded = upload(UPLOADED_SUBJECT);

        // then
        assertThat(ownerOf(uploaded)).isNull();
        assertThat(ownerChanges(uploaded)).isEmpty();
    }

    @Test
    void leavesCertificateWithoutOwner_whenTriggerClearsOwnerAndAnotherExecutionFails() throws Exception {
        // given
        enableAutomaticOwnership(true);
        startAuthService(UUID.randomUUID(), "trigger-owner");
        triggerSeeder.seedClearOwnerTriggerWithFailingExecution();

        // when
        Certificate uploaded = upload(UPLOADED_SUBJECT);

        // then
        assertThat(ownerOf(uploaded)).isNull();
        assertThat(ownerChanges(uploaded)).isEmpty();
    }

    @Test
    void leavesCertificateWithoutOwner_whenTriggerClearsOwnerAndAnotherItemOfTheExecutionFails() throws Exception {
        // given
        enableAutomaticOwnership(true);
        startAuthService(UUID.randomUUID(), "trigger-owner");
        triggerSeeder.seedClearOwnerTriggerWithFailingItem();

        // when
        Certificate uploaded = upload(UPLOADED_SUBJECT);

        // then
        assertThat(ownerOf(uploaded)).isNull();
        assertThat(ownerChanges(uploaded)).isEmpty();
    }

    @Test
    void makesUploaderOwner_whenOwnerClearingTriggerDoesNotMatch() throws Exception {
        // given
        enableAutomaticOwnership(true);
        NameAndUuidDto uploader = AuthHelper.getUserIdentification();
        startAuthService(UUID.randomUUID(), "trigger-owner");
        triggerSeeder.seedClearOwnerTriggerThatDoesNotMatch();

        // when
        Certificate uploaded = upload(UPLOADED_SUBJECT);

        // then
        assertThat(ownerOf(uploaded).getUuid()).isEqualTo(uploader.getUuid());
    }

    @Test
    void makesQueuedUploaderOwner_whenMessageIsProcessedWithoutSecurityContext() throws Exception {
        // given
        enableAutomaticOwnership(true);
        var uploaderUuid = UUID.fromString(AuthHelper.getUserIdentification().getUuid());
        var uploaderName = "queued-uploader";
        X509Certificate x509 = CertificateGeneratorHelper.generateCACertificate(null, "CN=queued");
        EventMessage message = uploadMessage(x509);
        startAuthService(uploaderUuid, uploaderName);
        // the queue consumer thread has no identity of its own
        SecurityContextHolder.clearContext();

        // when
        eventListener.processMessage(message);
        SecurityContextHolder.clearContext();

        // then
        Certificate uploaded = certificateRepository
                .findByFingerprint(CertificateUtil.getThumbprint(x509))
                .orElseThrow();
        assertThat(ownerOf(uploaded))
                .extracting(NameAndUuidDto::getUuid, NameAndUuidDto::getName)
                .containsExactly(uploaderUuid.toString(), uploaderName);
    }

    @Test
    void leavesCertificateWithoutOwner_whenUploaderIsNotKnown() throws Exception {
        // given
        enableAutomaticOwnership(true);
        SecurityContextHolder.clearContext();

        // when
        Certificate uploaded = upload(UPLOADED_SUBJECT);

        // then
        assertThat(ownerOf(uploaded)).isNull();
    }

    @Test
    void logsWarning_whenUploaderIsNotKnown() throws Exception {
        // given
        enableAutomaticOwnership(true);
        captureLogsOf(CertificateUploadedEventHandler.class);
        SecurityContextHolder.clearContext();

        // when
        upload(UPLOADED_SUBJECT);

        // then
        assertThat(capturedMessages()).anyMatch(message -> message.contains("uploader of certificate"));
    }

    @Test
    void keepsCertificate_whenStoringOwnerFails() throws Exception {
        // given
        Certificate uploaded = upload(UPLOADED_SUBJECT);
        var longerThanOwnerColumn = "u".repeat(300);
        var event = new UploaderOwnershipEvent(uploaded.getUuid(), UUID.randomUUID(), longerThanOwnerColumn);

        // when
        ThrowingCallable handleEvent = () -> uploaderOwnershipListener.handleUploaderOwnership(event);

        // then
        assertThatCode(handleEvent).doesNotThrowAnyException();
        assertThat(certificateRepository.findByUuid(uploaded.getUuid())).isPresent();
        assertThat(ownerOf(uploaded)).isNull();
    }

    @Test
    void logsWarning_whenStoringOwnerFails() throws Exception {
        // given
        Certificate uploaded = upload(UPLOADED_SUBJECT);
        var longerThanOwnerColumn = "u".repeat(300);
        captureLogsOf(UploaderOwnershipListener.class);

        // when
        uploaderOwnershipListener
                .handleUploaderOwnership(
                        new UploaderOwnershipEvent(uploaded.getUuid(), UUID.randomUUID(), longerThanOwnerColumn));

        // then
        assertThat(capturedMessages()).anyMatch(message -> message.contains("Unable to make"));
    }

    @Test
    void keepsExistingOwnerAndHistory_whenListenerHandlesOwnedCertificate() throws Exception {
        // given
        Certificate uploaded = upload(UPLOADED_SUBJECT);
        var existingOwnerName = "existing-owner";
        associationService.setOwner(Resource.CERTIFICATE, uploaded.getUuid(), UUID.randomUUID(), existingOwnerName);

        // when
        uploaderOwnershipListener
                .handleUploaderOwnership(new UploaderOwnershipEvent(uploaded.getUuid(), UUID.randomUUID(), "uploader"));

        // then
        assertThat(ownerOf(uploaded).getName()).isEqualTo(existingOwnerName);
        assertThat(ownerChanges(uploaded)).isEmpty();
    }

    @Test
    void opensCertificate_whenCallerOwnsItAndLacksDetailPermission() throws Exception {
        // given
        enableAutomaticOwnership(true);
        Certificate owned = upload(UPLOADED_SUBJECT);
        denyResourceAccess(Resource.CERTIFICATE, ResourceAction.DETAIL);

        // when
        CertificateDetailDto detail = certificateService.getCertificate(owned.getSecuredUuid());

        // then
        assertThat(detail.getUuid()).isEqualTo(owned.getUuid().toString());
    }

    @Test
    void deniesCertificate_whenCallerDoesNotOwnItAndLacksDetailPermission() throws Exception {
        // given
        Certificate notOwned = upload(UPLOADED_SUBJECT);
        denyResourceAccess(Resource.CERTIFICATE, ResourceAction.DETAIL);

        // when
        ThrowingCallable openCertificate = () -> certificateService.getCertificate(notOwned.getSecuredUuid());

        // then
        assertThatThrownBy(openCertificate).isInstanceOf(AuthorizationDeniedException.class);
    }

    // ── Helpers ───────────────────────────────────────────────────────────────

    private Certificate upload(String subject) throws Exception {
        X509Certificate x509 = CertificateGeneratorHelper.generateCACertificate(null, subject);

        certificateUploadedEventHandler.handleEvent(uploadMessage(x509));

        return certificateRepository.findByFingerprint(CertificateUtil.getThumbprint(x509)).orElseThrow();
    }

    private static EventMessage uploadMessage(X509Certificate x509) throws Exception {
        return CertificateUploadedEventHandler
                .constructEventMessage(CertificateUploadEventMessageData
                        .builder()
                        .certificateContent(Base64.getEncoder().encodeToString(x509.getEncoded()))
                        .build());
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

    private void startAuthService(UUID userUuid, String username) {
        authService = new WireMockServer(WireMockPorts.AUTH_SERVICE);
        authService.start();
        WireMock.configureFor("localhost", authService.port());
        AuthServiceWireMockStubs.stubImpersonation(authService, userUuid, username);
    }

    private NameAndUuidDto ownerOf(Certificate certificate) {
        return associationService.getOwner(Resource.CERTIFICATE, certificate.getUuid());
    }

    private List<String> ownerChanges(Certificate certificate) {
        return certificateEventHistoryRepository
                .findByCertificateOrderByCreatedDesc(certificate)
                .stream()
                .filter(history -> history.getEvent() == CertificateEvent.UPDATE_OWNER)
                .map(CertificateEventHistory::getMessage)
                .toList();
    }

    private void captureLogsOf(Class<?> source) {
        capturedLogger = (Logger) LoggerFactory.getLogger(source);
        capturedLogs = new ListAppender<>();
        capturedLogs.start();
        capturedLogger.addAppender(capturedLogs);
    }

    private List<String> capturedMessages() {
        return capturedLogs.list.stream().map(ILoggingEvent::getFormattedMessage).toList();
    }
}
