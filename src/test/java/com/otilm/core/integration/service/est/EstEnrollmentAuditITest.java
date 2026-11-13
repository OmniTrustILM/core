package com.otilm.core.integration.service.est;

import ch.qos.logback.classic.Level;
import ch.qos.logback.classic.Logger;
import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.core.read.ListAppender;
import com.github.tomakehurst.wiremock.WireMockServer;
import com.github.tomakehurst.wiremock.client.WireMock;
import com.otilm.api.interfaces.core.est.EstController;
import com.otilm.api.model.common.attribute.v2.DataAttributeV2;
import com.otilm.api.model.core.est.EstAuthenticationPolicy;
import com.otilm.api.model.core.logging.enums.AuditLogOutput;
import com.otilm.api.model.core.logging.enums.Operation;
import com.otilm.api.model.core.logging.records.LogRecord;
import com.otilm.api.model.core.settings.logging.AuditLoggingSettingsDto;
import com.otilm.api.model.core.settings.logging.LoggingSettingsDto;
import com.otilm.api.model.core.settings.logging.ResourceLoggingSettingsDto;
import com.otilm.core.dao.entity.RaProfile;
import com.otilm.core.dao.entity.Secret;
import com.otilm.core.dao.entity.est.EstProfile;
import com.otilm.core.messaging.jms.listeners.ActionsListener;
import com.otilm.core.messaging.jms.producers.ActionProducer;
import com.otilm.core.messaging.model.ActionMessage;
import com.otilm.core.messaging.model.AuditLogMessage;
import com.otilm.core.messaging.model.IssueActionData;
import com.otilm.core.model.auth.ResourceAction;
import com.otilm.core.service.SettingExternalService;
import com.otilm.core.service.est.enrollment.EstEnrollmentAudit;
import com.otilm.core.service.v2.ClientOperationInternalService;
import com.otilm.core.util.AttributeDefinitionUtils;
import com.otilm.core.util.BaseSpringBootTest;
import com.otilm.core.util.EstCsrFixtures;
import com.otilm.core.util.LoopbackWireMock;
import com.otilm.core.util.PkiFixtures;
import com.otilm.core.util.WireMockPorts;
import com.otilm.core.util.mockbeans.ProducerMocks;
import com.otilm.core.util.seeders.ApprovalProfileSeeder;
import com.otilm.core.util.seeders.EstRouteSeeder;
import com.otilm.core.util.seeders.SecretSeeder;
import java.nio.charset.StandardCharsets;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.UUID;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.filter.annotation.TypeExcludeFilters;
import org.springframework.context.annotation.Import;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;

import static com.otilm.core.util.EstClientCredentialsFixtures.basicAuthorization;
import static org.assertj.core.api.Assertions.assertThat;

/**
 * An answered {@code /simpleenroll} through the controller, so that the audit aspect runs, with the audit producer
 * capturing the record and a logger capturing what the enrolment says about itself.
 */
@Import(ProducerMocks.class)
@TypeExcludeFilters(ProducerMocks.MockedProducersTypeExcludeFilter.class)
class EstEnrollmentAuditITest extends BaseSpringBootTest {

    private static final String ESTPROFILE_NAME = "devices-profile";
    private static final String USERNAME = "device-owner";
    private static final String PASSWORD = "s3cret-audit-password";
    private static final String ISSUE_PATH = "/v2/authorityProvider/authorities/[^/]+/certificates/issue";

    @Autowired
    private EstController estController;

    @Autowired
    private EstRouteSeeder routes;

    @Autowired
    private SecretSeeder secrets;

    @Autowired
    private ClientOperationInternalService clientOperationService;

    @Autowired
    private ActionProducer actionProducer;

    @Autowired
    private SettingExternalService settingExternalService;

    @Autowired
    private ActionsListener actionsListener;

    @Autowired
    private ApprovalProfileSeeder approvals;

    private final List<AuditLogMessage> auditMessages = new ArrayList<>();
    private final ListAppender<ILoggingEvent> logs = new ListAppender<>();
    private final Logger platformLogger = (Logger) LoggerFactory.getLogger("com.otilm");
    private Level platformLevel;
    private WireMockServer authService;
    private WireMockServer connector;
    private RaProfile raProfile;
    private EstProfile estProfile;
    private Secret credential;

    @BeforeEach
    void seedRouteAndCaptureAudit() throws Exception {
        connector = LoopbackWireMock.start();
        X509Certificate issued = PkiFixtures.clientCertificate(PkiFixtures.rootCa("EST Issuing Root"));
        stubConnector("{ \"certificateData\": \"" + base64(issued) + "\" }");
        raProfile = routes.seedRaProfile(connector, "devices-ra");
        credential = secrets.seedBasicAuthSecret("ra-credential", USERNAME, PASSWORD);
        estProfile = routes.seedRaBasicEstProfile(ESTPROFILE_NAME, raProfile, credential);

        authService = new WireMockServer(WireMockPorts.AUTH_SERVICE);
        authService.start();

        auditLogsOn();
        Mockito.doAnswer(invocation -> {
            auditMessages.add(invocation.getArgument(0));
            return null;
        }).when(auditLogsProducer).produceMessage(Mockito.any());

        logs.start();
        platformLevel = platformLogger.getLevel();
        platformLogger.setLevel(Level.DEBUG);
        platformLogger.addAppender(logs);

        MockHttpServletRequest request = new MockHttpServletRequest();
        request.addHeader(HttpHeaders.AUTHORIZATION, basicAuthorization(USERNAME, PASSWORD));
        RequestContextHolder.setRequestAttributes(new ServletRequestAttributes(request));
    }

    @AfterEach
    void leaveTheRequest() {
        RequestContextHolder.resetRequestAttributes();
        platformLogger.detachAppender(logs);
        platformLogger.setLevel(platformLevel);
        authService.stop();
        connector.stop();
    }

    @Test
    void recordsIssuedOutcome_whenEnrolmentIsAnswered() throws Exception {
        // given
        issueAtOnce();

        // when
        ResponseEntity<byte[]> response = estController
                .simpleEnroll(estProfile.getName(), EstCsrFixtures.signedRequestBody());

        // then
        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK);
        assertThat(theEnrolmentRecord().operationData())
                .isEqualTo(new EstEnrollmentAudit(estProfile.getName(), EstAuthenticationPolicy.RA_BASIC,
                        theClientIdentity(), EstEnrollmentAudit.ISSUED));
    }

    @Test
    void recordsPendingOutcome_whenEnrolmentWaits() throws Exception {
        // given — the queued issue waits for an approval, so the enrolment is answered at once
        approvals.requireApproval(raProfile, UUID.randomUUID());
        deliverQueuedMessagesToTheListener();

        // when
        ResponseEntity<byte[]> response = estController
                .simpleEnroll(estProfile.getName(), EstCsrFixtures.signedRequestBody());

        // then
        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.ACCEPTED);
        assertThat(theEnrolmentRecord().operationData())
                .isEqualTo(new EstEnrollmentAudit(estProfile.getName(), EstAuthenticationPolicy.RA_BASIC,
                        theClientIdentity(), EstEnrollmentAudit.PENDING));
    }

    @Test
    void logsOutcomeOnce_whenEnrolmentIsAnswered() throws Exception {
        // given
        issueAtOnce();

        byte[] request = EstCsrFixtures.signedRequestBody();

        // when
        estController.simpleEnroll(estProfile.getName(), request);

        // then
        List<ILoggingEvent> infoLines = logs.list
                .stream()
                .filter(event -> event.getLevel() == Level.INFO)
                .filter(event -> event.getLoggerName().startsWith("com.otilm.core.service.est"))
                .toList();
        assertThat(infoLines)
                .singleElement()
                .satisfies(line -> assertThat(line.getFormattedMessage())
                        .contains(EstEnrollmentAudit.ISSUED, theClientIdentity(), estProfile.getName()));
        String everything = String.join("\n", logs.list.stream().map(ILoggingEvent::getFormattedMessage).toList());
        assertThat(everything).doesNotContain(PASSWORD).doesNotContain(new String(request, StandardCharsets.US_ASCII));
    }

    private void issueAtOnce() {
        Mockito.doAnswer(invocation -> {
            ActionMessage message = invocation.getArgument(0);
            if (message.getResourceAction() == ResourceAction.ISSUE) {
                clientOperationService
                        .issueCertificateAction(message.getResourceUuid(),
                                IssueActionData.certificateRequestUuidOf(message.getData()), false);
            }
            return null;
        }).when(actionProducer).produceMessage(Mockito.any());
    }

    /** Each queued message reaches the listener, as the broker consumer would deliver it. */
    private void deliverQueuedMessagesToTheListener() {
        Mockito.doAnswer(invocation -> {
            actionsListener.processMessage(invocation.getArgument(0));
            return null;
        }).when(actionProducer).produceMessage(Mockito.any());
    }

    private String theClientIdentity() {
        return "secret:" + credential.getUuid();
    }

    private LogRecord theEnrolmentRecord() {
        List<LogRecord> records = auditMessages
                .stream()
                .map(AuditLogMessage::getLogRecord)
                .filter(auditRecord -> auditRecord.operation() == Operation.ISSUE)
                .toList();
        assertThat(records).hasSize(1);
        return records.getFirst();
    }

    private void auditLogsOn() {
        AuditLoggingSettingsDto auditLogs = new AuditLoggingSettingsDto();
        auditLogs.setOutput(AuditLogOutput.ALL);
        auditLogs.setLogAllModules(true);
        auditLogs.setLogAllResources(true);
        LoggingSettingsDto settings = new LoggingSettingsDto();
        settings.setAuditLogs(auditLogs);
        settings.setEventLogs(new ResourceLoggingSettingsDto());
        settingExternalService.updateLoggingSettings(settings);
    }

    private void stubConnector(String issueAnswer) {
        connector.stubFor(WireMock.post(WireMock.urlPathMatching(ISSUE_PATH)).willReturn(WireMock.okJson(issueAnswer)));
        connector
                .stubFor(WireMock
                        .get(WireMock.urlPathMatching(ISSUE_PATH + "/attributes"))
                        .willReturn(WireMock.okJson(AttributeDefinitionUtils.serialize(List.<DataAttributeV2>of()))));
        connector
                .stubFor(WireMock
                        .post(WireMock.urlPathMatching(ISSUE_PATH + "/attributes/validate"))
                        .willReturn(WireMock.okJson("true")));
    }

    private static String base64(X509Certificate certificate) {
        try {
            return Base64.getEncoder().encodeToString(certificate.getEncoded());
        } catch (CertificateEncodingException e) {
            throw new IllegalStateException(e);
        }
    }
}
