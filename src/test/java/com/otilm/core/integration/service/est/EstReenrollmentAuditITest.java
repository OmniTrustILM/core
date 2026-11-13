package com.otilm.core.integration.service.est;

import ch.qos.logback.classic.Level;
import ch.qos.logback.classic.Logger;
import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.core.read.ListAppender;
import com.otilm.api.interfaces.core.est.EstController;
import com.otilm.api.model.core.est.EstAuthenticationPolicy;
import com.otilm.api.model.core.logging.enums.AuditLogOutput;
import com.otilm.api.model.core.logging.enums.Operation;
import com.otilm.api.model.core.logging.enums.OperationResult;
import com.otilm.api.model.core.logging.records.LogRecord;
import com.otilm.api.model.core.settings.logging.AuditLoggingSettingsDto;
import com.otilm.api.model.core.settings.logging.LoggingSettingsDto;
import com.otilm.api.model.core.settings.logging.ResourceLoggingSettingsDto;
import com.otilm.core.dao.entity.Certificate;
import com.otilm.core.dao.entity.RegistrationState;
import com.otilm.core.messaging.model.AuditLogMessage;
import com.otilm.core.service.SettingExternalService;
import com.otilm.core.service.est.enrollment.EstEnrollmentAudit;
import com.otilm.core.service.est.enrollment.EstReenrollmentAudit;
import com.otilm.core.service.est.message.EstError;
import com.otilm.core.service.est.message.EstException;
import com.otilm.core.util.CertificateUtil;
import com.otilm.core.util.PkiFixtures;
import com.otilm.core.util.mocks.AuthorityV2ConnectorStubs;
import com.otilm.core.util.seeders.CertificateRegistrationSeeder;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.UUID;
import org.assertj.core.api.ThrowableAssert.ThrowingCallable;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;

import static com.otilm.core.util.EstClientCredentialsFixtures.basicAuthorization;
import static com.otilm.core.util.EstClientCredentialsFixtures.certificateHeader;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * An answered or refused {@code /simplereenroll} through the controller, so that the audit aspect runs, with the audit
 * producer capturing the record and a logger capturing what the re-enrolment says about itself.
 */
class EstReenrollmentAuditITest extends AbstractEstReenrollmentITest {

    @Autowired
    private EstController estController;

    @Autowired
    private CertificateRegistrationSeeder registrations;

    @Autowired
    private SettingExternalService settingExternalService;

    @Value("${server.ssl.certificate-header-name}")
    private String certificateHeaderName;

    private static final String CLIENT_USERNAME = "device-1";
    private static final String PASSWORD = CertificateRegistrationSeeder.CHALLENGE;

    private final List<AuditLogMessage> auditMessages = new ArrayList<>();
    private final ListAppender<ILoggingEvent> logs = new ListAppender<>();
    private final Logger platformLogger = (Logger) LoggerFactory.getLogger("com.otilm");
    private Level platformLevel;

    @BeforeEach
    void captureAuditAndLogs() {
        turnAuditLogsOn();
        Mockito.doAnswer(invocation -> {
            auditMessages.add(invocation.getArgument(0));
            return null;
        }).when(auditLogsProducer).produceMessage(Mockito.any());

        logs.start();
        platformLevel = platformLogger.getLevel();
        platformLogger.setLevel(Level.DEBUG);
        platformLogger.addAppender(logs);
    }

    @AfterEach
    void leaveTheRequest() {
        RequestContextHolder.resetRequestAttributes();
        platformLogger.detachAppender(logs);
        platformLogger.setLevel(platformLevel);
    }

    @Test
    void auditsRenew_whenCsrCarriesTheSourceKey() throws Exception {
        // given
        X509Certificate source = issueDueCertificate(deviceKeys);
        Certificate seededSource = routes.seedIssuedCertificate(source, raProfile, estProfile);
        AuthorityV2ConnectorStubs.on(connector).stubRenew(issueFreshCertificate(deviceKeys));
        presentCertificate(source);

        // when
        ResponseEntity<byte[]> response = estController.simpleReenroll(estProfile.getName(), signRequest(deviceKeys));

        // then
        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK);
        LogRecord auditRecord = findTheReenrollmentRecord();
        assertThat(auditRecord.operation()).isEqualTo(Operation.RENEW);
        assertThat(auditRecord.operationResult()).isEqualTo(OperationResult.SUCCESS);
        assertThat(auditRecord.operationData())
                .isEqualTo(new EstReenrollmentAudit(estProfile.getName(), estProfile.getAuthenticationPolicy(),
                        deriveClientIdentity(source), seededSource.getUuid(), EstEnrollmentAudit.ISSUED));
    }

    @Test
    void auditsRekey_whenCsrCarriesANewKey() throws Exception {
        // given
        X509Certificate source = issueDueCertificate(deviceKeys);
        Certificate seededSource = routes.seedIssuedCertificate(source, raProfile, estProfile);
        KeyPair newKeys = PkiFixtures.keyPair();
        AuthorityV2ConnectorStubs.on(connector).stubRenew(issueFreshCertificate(newKeys));
        presentCertificate(source);

        // when
        ResponseEntity<byte[]> response = estController.simpleReenroll(estProfile.getName(), signRequest(newKeys));

        // then
        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK);
        LogRecord auditRecord = findTheReenrollmentRecord();
        assertThat(auditRecord.operation()).isEqualTo(Operation.REKEY);
        assertThat(auditRecord.operationResult()).isEqualTo(OperationResult.SUCCESS);
        assertThat(auditRecord.operationData())
                .isEqualTo(new EstReenrollmentAudit(estProfile.getName(), estProfile.getAuthenticationPolicy(),
                        deriveClientIdentity(source), seededSource.getUuid(), EstEnrollmentAudit.ISSUED));
    }

    @Test
    void auditsRekey_whenRetryOfARekeyIsAnswered() throws Exception {
        // given
        X509Certificate source = issueDueCertificate(deviceKeys);
        Certificate seededSource = routes.seedIssuedCertificate(source, raProfile, estProfile);
        KeyPair newKeys = PkiFixtures.keyPair();
        AuthorityV2ConnectorStubs.on(connector).stubRenew(issueFreshCertificate(newKeys));
        byte[] requestWithANewKey = signRequest(newKeys);
        presentCertificate(source);
        estController.simpleReenroll(estProfile.getName(), requestWithANewKey);
        auditMessages.clear();
        presentCertificate(source);

        // when
        ResponseEntity<byte[]> retry = estController.simpleReenroll(estProfile.getName(), requestWithANewKey);

        // then
        assertThat(retry.getStatusCode()).isEqualTo(HttpStatus.OK);
        LogRecord auditRecord = findTheReenrollmentRecord();
        assertThat(auditRecord.operation()).isEqualTo(Operation.REKEY);
        assertThat(auditRecord.operationResult()).isEqualTo(OperationResult.SUCCESS);
        assertThat(auditRecord.operationData())
                .isEqualTo(new EstReenrollmentAudit(estProfile.getName(), estProfile.getAuthenticationPolicy(),
                        deriveClientIdentity(source), seededSource.getUuid(), EstEnrollmentAudit.ISSUED));
    }

    @Test
    void auditsRekeyFailure_whenProfileForbidsRekey() throws Exception {
        // given
        estProfile.setAllowRekey(false);
        estProfile = estProfileRepository.save(estProfile);
        X509Certificate source = issueDueCertificate(deviceKeys);
        routes.seedIssuedCertificate(source, raProfile, estProfile);
        byte[] requestWithANewKey = signRequest(PkiFixtures.keyPair());
        presentCertificate(source);

        // when
        ThrowingCallable reenroll = () -> estController.simpleReenroll(estProfile.getName(), requestWithANewKey);

        // then
        assertThatThrownBy(reenroll)
                .isInstanceOfSatisfying(EstException.class,
                        refusal -> assertThat(refusal.error()).isEqualTo(EstError.REKEY_NOT_ALLOWED));
        LogRecord auditRecord = findTheReenrollmentRecord();
        assertThat(auditRecord.operation()).isEqualTo(Operation.REKEY);
        assertThat(auditRecord.operationResult()).isEqualTo(OperationResult.FAILURE);
    }

    @Test
    void auditsRenewFailure_whenRefusedBeforeClassification() throws Exception {
        // given — no client certificate, so the request is refused before it is classified
        RequestContextHolder.setRequestAttributes(new ServletRequestAttributes(new MockHttpServletRequest()));
        byte[] requestWithANewKey = signRequest(PkiFixtures.keyPair());

        // when
        ThrowingCallable reenroll = () -> estController.simpleReenroll(estProfile.getName(), requestWithANewKey);

        // then
        assertThatThrownBy(reenroll)
                .isInstanceOfSatisfying(EstException.class,
                        refusal -> assertThat(refusal.error()).isEqualTo(EstError.CERTIFICATE_REJECTED));
        LogRecord auditRecord = findTheReenrollmentRecord();
        assertThat(auditRecord.operation()).isEqualTo(Operation.RENEW);
        assertThat(auditRecord.operationResult()).isEqualTo(OperationResult.FAILURE);
    }

    @Test
    void logsOutcomeOnce_whenReenrolmentIsAnswered() throws Exception {
        // given — a registration guards the source, so the password of the client reaches the renewal
        authenticateBy(EstAuthenticationPolicy.CERTIFICATE_REGISTRATION);
        X509Certificate source = issueDueCertificate(deviceKeys);
        Certificate seededSource = routes.seedIssuedCertificate(source, raProfile, estProfile);
        registrations.seedRetainedAuthorization(seededSource, RegistrationState.ACTIVE);
        X509Certificate renewed = issueFreshCertificate(deviceKeys);
        AuthorityV2ConnectorStubs.on(connector).stubRenew(renewed);
        byte[] request = signRequest(deviceKeys);
        presentCertificate(source, basicAuthorization(CLIENT_USERNAME, PASSWORD));

        // when
        estController.simpleReenroll(estProfile.getName(), request);

        // then
        List<ILoggingEvent> estLines = logs.list
                .stream()
                .filter(event -> event.getLoggerName().startsWith("com.otilm.core.service.est"))
                .toList();
        List<ILoggingEvent> infoLines = estLines.stream().filter(event -> event.getLevel() == Level.INFO).toList();
        UUID successorUuid = findTheOnlyCertificateBesides(seededSource).getUuid();
        assertThat(infoLines)
                .singleElement()
                .satisfies(line -> assertThat(line.getFormattedMessage())
                        .contains(EstEnrollmentAudit.ISSUED, "renewal", seededSource.getUuid().toString(),
                                successorUuid.toString(), deriveClientIdentity(source), estProfile.getName()));
        List<String> everything = logs.list.stream().map(ILoggingEvent::getFormattedMessage).toList();
        List<String> estMessages = estLines.stream().map(ILoggingEvent::getFormattedMessage).toList();
        assertThat(everything).isNotEmpty().noneMatch(line -> line.contains(PASSWORD));
        assertThat(everything).noneMatch(line -> line.contains(encodeBasicCredentials()));
        assertThat(everything).noneMatch(line -> line.contains(new String(request, StandardCharsets.US_ASCII)));
        assertThat(everything).noneMatch(line -> line.contains(certificateHeader(source)));
        String issuedCertificateBody = encodeBase64Der(renewed);
        assertThat(estMessages).noneMatch(line -> line.contains(issuedCertificateBody));
    }

    // ── Helpers ───────────────────────────────────────────────────────────────

    /** The request that the proxy forwards: it carries the certificate that the client renews. */
    private void presentCertificate(X509Certificate certificate) {
        presentCertificate(certificate, null);
    }

    /** As the proxy forwards it, with the Basic credentials that the client sent when it sent any. */
    private void presentCertificate(X509Certificate certificate, String authorization) {
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.addHeader(certificateHeaderName, certificateHeader(certificate));
        if (authorization != null) {
            request.addHeader(HttpHeaders.AUTHORIZATION, authorization);
        }
        RequestContextHolder.setRequestAttributes(new ServletRequestAttributes(request));
    }

    private static String encodeBasicCredentials() {
        return Base64.getEncoder().encodeToString((CLIENT_USERNAME + ":" + PASSWORD).getBytes(StandardCharsets.UTF_8));
    }

    private static String encodeBase64Der(X509Certificate certificate) throws Exception {
        return Base64.getEncoder().encodeToString(certificate.getEncoded());
    }

    private static String deriveClientIdentity(X509Certificate source) throws Exception {
        return "certificate:" + CertificateUtil.getThumbprint(source);
    }

    private LogRecord findTheReenrollmentRecord() {
        List<LogRecord> records = auditMessages
                .stream()
                .map(AuditLogMessage::getLogRecord)
                .filter(auditRecord -> auditRecord.operation() == Operation.RENEW
                        || auditRecord.operation() == Operation.REKEY)
                .toList();
        assertThat(records).hasSize(1);
        return records.getFirst();
    }

    private void turnAuditLogsOn() {
        AuditLoggingSettingsDto auditLogs = new AuditLoggingSettingsDto();
        auditLogs.setOutput(AuditLogOutput.ALL);
        auditLogs.setLogAllModules(true);
        auditLogs.setLogAllResources(true);
        LoggingSettingsDto settings = new LoggingSettingsDto();
        settings.setAuditLogs(auditLogs);
        settings.setEventLogs(new ResourceLoggingSettingsDto());
        settingExternalService.updateLoggingSettings(settings);
    }
}
