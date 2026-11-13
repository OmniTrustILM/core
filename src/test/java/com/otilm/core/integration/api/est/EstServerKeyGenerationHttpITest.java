package com.otilm.core.integration.api.est;

import ch.qos.logback.classic.Level;
import ch.qos.logback.classic.Logger;
import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.classic.spi.ThrowableProxyUtil;
import ch.qos.logback.core.read.ListAppender;
import com.github.tomakehurst.wiremock.WireMockServer;
import com.otilm.api.model.client.cryptography.key.KeyRequestType;
import com.otilm.api.model.common.enums.cryptography.KeyAlgorithm;
import com.otilm.api.model.common.enums.cryptography.SignatureAlgorithm;
import com.otilm.api.model.core.est.EstAuthenticationPolicy;
import com.otilm.api.model.core.est.EstMediaTypes;
import com.otilm.api.model.core.logging.enums.AuditLogOutput;
import com.otilm.api.model.core.settings.logging.AuditLoggingSettingsDto;
import com.otilm.api.model.core.settings.logging.LoggingSettingsDto;
import com.otilm.api.model.core.settings.logging.ResourceLoggingSettingsDto;
import com.otilm.core.dao.entity.RaProfile;
import com.otilm.core.dao.entity.Secret;
import com.otilm.core.dao.entity.TokenProfile;
import com.otilm.core.dao.repository.AuditLogRepository;
import com.otilm.core.dao.repository.est.EstProfileRepository;
import com.otilm.core.messaging.model.ActionMessage;
import com.otilm.core.messaging.model.AuditLogMessage;
import com.otilm.core.messaging.model.IssueActionData;
import com.otilm.core.serialization.ObjectMapperFactory;
import com.otilm.core.service.SettingExternalService;
import com.otilm.core.service.est.message.EstError;
import com.otilm.core.service.v2.ClientOperationInternalService;
import com.otilm.core.util.EstCsrFixtures;
import com.otilm.core.util.LoopbackWireMock;
import com.otilm.core.util.PkiFixtures;
import com.otilm.core.util.mocks.AuthorityV2ConnectorStubs;
import com.otilm.core.util.mocks.CertifyingIssueTransformer;
import com.otilm.core.util.mocks.ConnectorMockFactory;
import com.otilm.core.util.mocks.CryptographyProviderV2ConnectorMock;
import com.otilm.core.util.seeders.ApprovalProfileSeeder;
import com.otilm.core.util.seeders.SecretSeeder;
import com.otilm.core.util.seeders.TokenProfileSeeder;
import com.zaxxer.hikari.HikariDataSource;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.KeyPair;
import java.security.cert.X509Certificate;
import java.sql.SQLException;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.Collection;
import java.util.HexFormat;
import java.util.List;
import java.util.Locale;
import java.util.UUID;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.stream.IntStream;
import javax.sql.DataSource;
import org.awaitility.Awaitility;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.asn1.sec.ECPrivateKey;
import org.bouncycastle.asn1.x9.ECNamedCurveTable;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.mime.BasicMimeParser;
import org.bouncycastle.mime.ConstantMimeContext;
import org.bouncycastle.mime.Headers;
import org.bouncycastle.mime.MimeContext;
import org.bouncycastle.mime.MimeParserContext;
import org.bouncycastle.mime.MimeParserListener;
import org.bouncycastle.util.BigIntegers;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jms.core.JmsTemplate;
import org.springframework.jms.core.MessagePostProcessor;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.test.web.servlet.request.MockHttpServletRequestBuilder;

import static com.otilm.core.util.EstClientCredentialsFixtures.basicAuthorization;
import static com.otilm.core.util.EstServerKeyGenerationAnswers.isKeyOf;
import static com.otilm.core.util.builders.EstProfileBuilder.anEstProfile;
import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.atLeast;
import static org.mockito.Mockito.timeout;
import static org.mockito.Mockito.verify;

/**
 * {@code /serverkeygen} over HTTP through the real filter and interceptor chain, in memory and with key recovery,
 * against an authority double that certifies the request it is sent. Nothing here consumes the issue that a request
 * queues, so each test takes it from the mocked broker and issues it as the consumer would while the request waits. The
 * answer is read with BouncyCastle's MIME parser, which shares no code with the writer of the answer.
 */
class EstServerKeyGenerationHttpITest extends AbstractEstHttpITest {

    private static final String LABEL = "devices";
    private static final String RA_PROFILE_NAME = "devices-ra";
    private static final String USERNAME = "device-owner";
    private static final String PASSWORD = "p4ssw0rd";
    private static final String CLIENT_SUBJECT = "CN=device-1";
    private static final String ECDSA_SIGNATURE = "SHA256withECDSA";
    private static final int P256_LENGTH = 256;
    private static final String CONTENT_TRANSFER_ENCODING = "Content-Transfer-Encoding";
    private static final Duration QUEUE_TIMEOUT = Duration.ofSeconds(10);
    private static final Duration ANSWER_TIMEOUT = Duration.ofSeconds(30);
    /** A key generation answers a timeout within moments, so a test of it does not wait the default 30 s. */
    private static final int SERVER_KEY_GENERATION_TIMEOUT_SECONDS = 5;
    private static final int POOL_SAMPLES = 20;
    private static final Duration POOL_SAMPLE_INTERVAL = Duration.ofMillis(50);
    private static final Duration POOL_SAMPLING_TIMEOUT = Duration.ofSeconds(10);

    private static final List<String> TRACED_LOGGERS = List
            .of("com.otilm", "org.springframework.web", "org.hibernate.orm.jdbc.bind");

    private static WireMockServer certifyingAuthority;

    @Autowired
    private SecretSeeder secrets;

    @Autowired
    private EstProfileRepository estProfileRepository;

    @Autowired
    private TokenProfileSeeder tokenProfiles;

    @Autowired
    private ConnectorMockFactory connectorMockFactory;

    @Autowired
    private ApprovalProfileSeeder approvals;

    @Autowired
    private ClientOperationInternalService clientOperationService;

    @Autowired
    private JmsTemplate jmsTemplate;

    @Autowired
    private DataSource dataSource;

    @Autowired
    private SettingExternalService settingService;

    @Autowired
    private JdbcTemplate jdbcTemplate;

    @Autowired
    private AuditLogRepository auditLogRepository;

    private final ExecutorService requestThread = Executors.newSingleThreadExecutor();
    private final KeyPair tokenKeyPair = PkiFixtures.keyPair();
    private RaProfile raProfile;
    private Secret credential;
    private CryptographyProviderV2ConnectorMock token;

    @BeforeAll
    static void startCertifyingAuthority() {
        certifyingAuthority = LoopbackWireMock
                .start(new CertifyingIssueTransformer(PkiFixtures.rootCa("EST Server Keygen Root")));
    }

    @AfterAll
    static void stopCertifyingAuthority() {
        certifyingAuthority.stop();
    }

    @BeforeEach
    void seedRaProfileOnTheCertifyingAuthority() {
        certifyingAuthority.resetAll();
        AuthorityV2ConnectorStubs
                .on(certifyingAuthority)
                .stubIssueCertifyingTheRequest()
                .stubIssueAttributeValidation();
        raProfile = seeder.seedRaProfile(certifyingAuthority, RA_PROFILE_NAME);
        credential = secrets.seedBasicAuthSecret("ra-credential", USERNAME, PASSWORD);
    }

    /** Interrupts a request that still waits, so that it ends before the next test cleans the database. */
    @AfterEach
    void stopTheRequestThreadAndTheToken() throws InterruptedException {
        requestThread.shutdownNow();
        if (!requestThread.awaitTermination(ANSWER_TIMEOUT.toSeconds(), TimeUnit.SECONDS)) {
            throw new IllegalStateException("The key generation request did not stop");
        }
        if (token != null) {
            token.stop();
        }
    }

    // ── Delivery ──────────────────────────────────────────────────────────────

    @Nested
    class Delivery {

        @Test
        void answersWithTheKeyThenItsCertificateInMultipartMixed_whenGeneratedInMemory() throws Exception {
            // given
            seedRoute(null);

            // when
            MockHttpServletResponse response = generateAndIssueAsTheConsumerWould();

            // then
            assertThat(response.getStatus()).isEqualTo(200);
            MediaType contentType = MediaType.parseMediaType(response.getContentType());
            assertThat(contentType.getType() + "/" + contentType.getSubtype()).isEqualTo(EstMediaTypes.MULTIPART_MIXED);
            assertThat(contentType.getParameter("boundary")).isNotBlank();
            assertThat(response.getHeader(HttpHeaders.CACHE_CONTROL)).isEqualTo("no-store");
            List<Part> parts = parseMultipart(response);
            assertThat(parts).hasSize(2);
            assertThat(parts.get(0).contentType()).isEqualTo(EstMediaTypes.PKCS8);
            assertThat(parts.get(0).transferEncoding()).isEqualTo("base64");
            assertThat(parts.get(1).contentType()).isEqualTo(EstMediaTypes.PKCS7_CERTS_ONLY);
            assertThat(parts.get(1).transferEncoding()).isEqualTo("base64");
            X509Certificate certificate = theOnlyCertificateOf(parts.get(1));
            assertThat(isKeyOf(parts.get(0).content(), certificate, ECDSA_SIGNATURE)).isTrue();
        }

        @Test
        void answersWithTheTokenKeyAndItsCertificate_whenRecoveringKeys() throws Exception {
            // given
            seedRoute(startExportingToken());

            // when
            MockHttpServletResponse response = generateAndIssueAsTheConsumerWould();

            // then
            assertThat(response.getStatus()).isEqualTo(200);
            assertThat(response.getHeader(HttpHeaders.CACHE_CONTROL)).isEqualTo("no-store");
            List<Part> parts = parseMultipart(response);
            assertThat(parts).hasSize(2);
            X509Certificate certificate = theOnlyCertificateOf(parts.get(1));
            assertThat(certificate.getPublicKey().getEncoded()).isEqualTo(tokenKeyPair.getPublic().getEncoded());
            assertThat(isKeyOf(parts.get(0).content(), certificate, ECDSA_SIGNATURE)).isTrue();
        }
    }

    // ── Refusals ──────────────────────────────────────────────────────────────

    @Nested
    class Refusals {

        @Test
        void refusesAsDisabled_whenTheEstProfileDoesNotGenerateKeys() throws Exception {
            // given
            seeder.seedRaBasicEstProfile(LABEL, raProfile, credential);

            // when
            MockHttpServletResponse response = postToEst(LABEL + "/serverkeygen",
                    EstCsrFixtures.signedRequestBody(CLIENT_SUBJECT), basicAuthorization(USERNAME, PASSWORD));

            // then
            assertPlainTextError(response, EstError.SERVER_KEYGEN_DISABLED);
        }

        @Test
        void refusesAsUnavailable_whenTheRaProfileAsksForAnApproval() throws Exception {
            // given
            seedRoute(null);
            approvals.requireApproval(raProfile, UUID.randomUUID());

            // when
            MockHttpServletResponse response = postToEst(LABEL + "/serverkeygen",
                    EstCsrFixtures.signedRequestBody(CLIENT_SUBJECT), basicAuthorization(USERNAME, PASSWORD));

            // then
            assertPlainTextError(response, EstError.SERVER_KEYGEN_UNAVAILABLE);
        }

        @Test
        void refusesAsBadRequest_whenTheClientAsksForEncryptedDelivery() throws Exception {
            // given
            seedRoute(null);
            byte[] askingForEncryption = EstCsrFixtures
                    .signedRequestBodyWithAttribute(CLIENT_SUBJECT, "device-1.example",
                            PKCSObjectIdentifiers.id_aa.branch("37"), new DEROctetString(new byte[]{1, 2, 3}));

            // when
            MockHttpServletResponse response = postToEst(LABEL + "/serverkeygen", askingForEncryption,
                    basicAuthorization(USERNAME, PASSWORD));

            // then
            assertPlainTextError(response, EstError.ENCRYPTED_KEY_DELIVERY_UNSUPPORTED);
        }

        @Test
        void refusesAsTimedOut_whenTheQueuedIssueIsNotConsumedInTime() throws Exception {
            // given — nothing consumes the queued issue, so the certificate is not issued within the bound
            seedRoute(null);

            // when
            MockHttpServletResponse response = postToEst(LABEL + "/serverkeygen",
                    EstCsrFixtures.signedRequestBody(CLIENT_SUBJECT), basicAuthorization(USERNAME, PASSWORD));

            // then
            assertPlainTextError(response, EstError.ISSUANCE_TIMED_OUT);
        }
    }

    // ── ConnectionPool ────────────────────────────────────────────────────────

    @Nested
    class ConnectionPool {

        @Test
        void holdsNoPooledConnection_whenTheRequestWaitsForTheCertificateInMemory() throws Exception {
            // given — the queued issue stays open until the test issues it
            seedRoute(null);

            // when, then
            assertNoPooledConnectionHeldWhileWaiting();
        }

        @Test
        void holdsNoPooledConnection_whenTheRequestWaitsForTheCertificateWithKeyRecovery() throws Exception {
            // given — the queued issue stays open until the test issues it
            seedRoute(startExportingToken());

            // when, then
            assertNoPooledConnectionHeldWhileWaiting();
        }

        // ── Helpers ───────────────────────────────────────────────────────────

        private void assertNoPooledConnectionHeldWhileWaiting() throws Exception {
            int idle = countIdleConnections();
            Future<MockHttpServletResponse> generation = generateInTheBackground();
            ActionMessage queued = awaitQueuedIssue();
            List<Integer> inUseWhileWaiting = sampleActiveConnections();
            issueAsTheConsumerWould(queued);
            MockHttpServletResponse response = generation.get(ANSWER_TIMEOUT.toSeconds(), TimeUnit.SECONDS);

            assertThat(inUseWhileWaiting)
                    .as("connections in use while the request waits, against %d when idle", idle)
                    .filteredOn(inUse -> inUse > idle)
                    .hasSizeLessThan(POOL_SAMPLES / 2);
            assertThat(response.getStatus()).isEqualTo(200);
        }

        /** The fewest connections in use among a few samples, so that a background task does not raise it. */
        private int countIdleConnections() {
            return sampleActiveConnections().stream().mapToInt(Integer::intValue).min().orElseThrow();
        }

        private List<Integer> sampleActiveConnections() {
            List<Integer> samples = new ArrayList<>();
            Awaitility.await().atMost(POOL_SAMPLING_TIMEOUT).pollInterval(POOL_SAMPLE_INTERVAL).until(() -> {
                samples.add(countActiveConnections());
                return samples.size() >= POOL_SAMPLES;
            });
            return samples;
        }

        private int countActiveConnections() throws SQLException {
            return dataSource.unwrap(HikariDataSource.class).getHikariPoolMXBean().getActiveConnections();
        }
    }

    // ── KeyMaterialInLogs ─────────────────────────────────────────────────────

    /**
     * Every platform logger at TRACE, which turns on the request and response lines, the body advice and the controller
     * logging advice, with verbose audit records. A failure names only where key material was found, so that the test
     * report does not carry it either.
     */
    @Nested
    class KeyMaterialInLogs {

        private final ListAppender<ILoggingEvent> logs = new ListAppender<>();
        private final Logger root = (Logger) LoggerFactory.getLogger(org.slf4j.Logger.ROOT_LOGGER_NAME);
        private final List<Logger> traced = TRACED_LOGGERS
                .stream()
                .map(name -> (Logger) LoggerFactory.getLogger(name))
                .toList();
        private final List<Level> previousLevels = new ArrayList<>();

        @BeforeEach
        void traceEverythingAndAuditVerbosely() {
            verboseAuditLogs();
            logs.start();
            root.addAppender(logs);
            for (Logger logger : traced) {
                previousLevels.add(logger.getLevel());
                logger.setLevel(Level.TRACE);
            }
        }

        /** The loggers are process-wide singletons; the settings go with the database that the next test clears. */
        @AfterEach
        void restoreTheLoggers() {
            for (int index = 0; index < traced.size(); index++) {
                traced.get(index).setLevel(previousLevels.get(index));
            }
            root.detachAppender(logs);
            logs.stop();
        }

        @Test
        void logsAndAuditsNoKeyMaterial_whenGeneratedInMemory() throws Exception {
            // given
            seedRoute(null);

            // when
            MockHttpServletResponse response = generateAndIssueAsTheConsumerWould();

            // then
            assertThat(response.getStatus()).isEqualTo(200);
            KeyMaterial keyMaterial = keyMaterialOf(response);
            assertNoneCarries("log lines", capturedLines(), keyMaterial);
            assertNoneCarries("audit records", auditRecords(), keyMaterial);
            assertTracedAndAudited("in-memory");
        }

        @Test
        void logsAndAuditsNeitherKeyMaterialNorTransportPassphrase_whenRecoveringKeys() throws Exception {
            // given
            seedRoute(startExportingToken());

            // when
            MockHttpServletResponse response = generateAndIssueAsTheConsumerWould();

            // then
            assertThat(response.getStatus()).isEqualTo(200);
            List<String> transportPassphrases = token.exportPassphrasesReceived();
            assertThat(transportPassphrases).as("exports sent").hasSize(1);
            assertThat(transportPassphrases.getFirst()).as("transport passphrase").isNotBlank();
            KeyMaterial keyMaterial = keyMaterialOf(response)
                    .withPrivateKey(tokenKeyPair.getPrivate().getEncoded())
                    .withVerbatim(transportPassphrases);
            assertNoneCarries("log lines", capturedLines(), keyMaterial);
            assertNoneCarries("audit records", auditRecords(), keyMaterial);
            assertTracedAndAudited("key-recovery");
        }

        // ── Helpers ───────────────────────────────────────────────────────────

        /**
         * The request reached every logger that the test turned on, and its audit record names the mode. It runs after
         * the leak checks, as a failure of it prints what was captured.
         */
        private void assertTracedAndAudited(String mode) throws Exception {
            List<String> lines = capturedLines();
            assertThat(lines).as("the request was traced").anyMatch(line -> line.startsWith("REQUEST DATA"));
            assertThat(lines).as("the response was traced").anyMatch(line -> line.startsWith("RESPONSE DATA"));
            assertThat(lines)
                    .as("the controller logging advice traced the answer")
                    .anyMatch(line -> line.contains("serverKeyGeneration() result"));
            assertThat(auditRecords()).as("the audit record of the request").anyMatch(line -> line.contains(mode));
            assertThat(auditLogRepository.findAll())
                    .as("verbose audit records the parameters of the request")
                    .anyMatch(auditLog -> auditLog.getLogRecord().additionalData() != null
                            && LABEL.equals(auditLog.getLogRecord().additionalData().get("label")));
        }

        /**
         * Every captured line with its arguments, its MDC and the stack trace of its exception, if it has one. The copy
         * is taken under the lock that the appender appends under, as other threads may still log.
         */
        private List<String> capturedLines() {
            List<ILoggingEvent> events;
            synchronized (logs) {
                events = List.copyOf(logs.list);
            }
            List<String> lines = new ArrayList<>();
            for (ILoggingEvent event : events) {
                lines.add(event.getFormattedMessage() + " " + event.getMDCPropertyMap());
                if (event.getThrowableProxy() != null) {
                    lines.add(ThrowableProxyUtil.asString(event.getThrowableProxy()));
                }
            }
            return lines;
        }

        /** Every audit record written to the database, each row as text, and every one queued. */
        private List<String> auditRecords() throws Exception {
            List<String> records = new ArrayList<>(jdbcTemplate
                    .queryForList("SELECT CAST(a AS text) FROM %s.audit_log a".formatted(dbSchema), String.class));
            ArgumentCaptor<AuditLogMessage> queued = ArgumentCaptor.forClass(AuditLogMessage.class);
            verify(auditLogsProducer, atLeast(0)).produceMessage(queued.capture());
            for (AuditLogMessage message : queued.getAllValues()) {
                records.add(ObjectMapperFactory.auditLog().writeValueAsString(message));
            }
            return records;
        }

        private void verboseAuditLogs() {
            AuditLoggingSettingsDto auditLogs = new AuditLoggingSettingsDto();
            auditLogs.setOutput(AuditLogOutput.ALL);
            auditLogs.setLogAllModules(true);
            auditLogs.setLogAllResources(true);
            auditLogs.setVerbose(true);
            LoggingSettingsDto settings = new LoggingSettingsDto();
            settings.setAuditLogs(auditLogs);
            settings.setEventLogs(new ResourceLoggingSettingsDto());
            settingService.updateLoggingSettings(settings);
        }
    }

    // ── Helpers ───────────────────────────────────────────────────────────────

    /** @param keyRecoveryTokenProfile the token profile that keeps the keys, {@code null} to generate them in memory */
    private void seedRoute(TokenProfile keyRecoveryTokenProfile) {
        estProfileRepository
                .save(anEstProfile()
                        .withName(LABEL)
                        .withEnabled(true)
                        .withRaProfile(raProfile)
                        .withAuthenticationPolicy(EstAuthenticationPolicy.RA_BASIC)
                        .withBasicCredentialSecrets(credential.getUuid())
                        .withServerKeyGeneration(true)
                        .withServerKeyGenerationTimeout(SERVER_KEY_GENERATION_TIMEOUT_SECONDS)
                        .withKeyRecovery(keyRecoveryTokenProfile != null)
                        .withKeyRecoveryTokenProfile(keyRecoveryTokenProfile)
                        .build());
    }

    /** A v2 token double that signs with a key the test holds and exports it under the passphrase it is sent. */
    private TokenProfile startExportingToken() throws Exception {
        token = connectorMockFactory.startCryptographyProviderV2();
        token
                .stubCreateKeyPair(tokenKeyPair.getPublic(), KeyAlgorithm.ECDSA, P256_LENGTH)
                .stubExportableKeyTypes(KeyRequestType.KEY_PAIR, KeyAlgorithm.ECDSA)
                .stubSignatureAlgorithmAttribute(SignatureAlgorithm.SHA256_WITH_ECDSA)
                .stubRealSigning(tokenKeyPair.getPrivate(), SignatureAlgorithm.SHA256_WITH_ECDSA)
                .stubExportKeyAttributes("[]")
                .stubExportOf(tokenKeyPair, KeyAlgorithm.ECDSA, P256_LENGTH)
                .stubDestroyKey();
        return tokenProfiles.seedKeyExportingTokenProfile(token.getUrl(), KeyAlgorithm.ECDSA);
    }

    private MockHttpServletResponse generateAndIssueAsTheConsumerWould() throws Exception {
        Future<MockHttpServletResponse> generation = generateInTheBackground();
        issueAsTheConsumerWould(awaitQueuedIssue());
        return generation.get(ANSWER_TIMEOUT.toSeconds(), TimeUnit.SECONDS);
    }

    private Future<MockHttpServletResponse> generateInTheBackground() throws Exception {
        MockHttpServletRequestBuilder generation = estPost(LABEL + "/serverkeygen",
                EstCsrFixtures.signedRequestBody(CLIENT_SUBJECT))
                .header(HttpHeaders.AUTHORIZATION, basicAuthorization(USERNAME, PASSWORD));
        return requestThread.submit(() -> mockMvc.perform(generation).andReturn().getResponse());
    }

    /** The issue that the request queued, taken from the broker as its consumer would take it. */
    private ActionMessage awaitQueuedIssue() {
        ArgumentCaptor<ActionMessage> queued = ArgumentCaptor.forClass(ActionMessage.class);
        verify(jmsTemplate, timeout(QUEUE_TIMEOUT.toMillis()))
                .convertAndSend(anyString(), queued.capture(), any(MessagePostProcessor.class));
        return queued.getValue();
    }

    /** Issues for the request that the issue was queued for, as the actions listener does. */
    private void issueAsTheConsumerWould(ActionMessage queued) throws Exception {
        clientOperationService
                .issueCertificateAction(queued.getResourceUuid(),
                        IssueActionData.certificateRequestUuidOf(queued.getData()), false);
    }

    /** One part of the answer, with its content decoded from its transfer encoding. */
    private record Part(String contentType, String transferEncoding, byte[] content) {
    }

    /** The parser reads only a quoted boundary, so the boundary of the answer is handed to it quoted. */
    private static List<Part> parseMultipart(MockHttpServletResponse response) throws IOException {
        List<Part> parts = new ArrayList<>();
        String boundary = MediaType.parseMediaType(response.getContentType()).getParameter("boundary");
        String contentType = "%s; boundary=\"%s\"".formatted(EstMediaTypes.MULTIPART_MIXED, boundary);
        Headers headers = new Headers(List.of(HttpHeaders.CONTENT_TYPE + ": " + contentType), "7bit");
        new BasicMimeParser(headers, new ByteArrayInputStream(response.getContentAsByteArray()))
                .parse(new MimeParserListener() {
                    @Override
                    public MimeContext createContext(MimeParserContext parserContext, Headers partHeaders) {
                        return ConstantMimeContext.Instance;
                    }

                    @Override
                    public void object(MimeParserContext parserContext, Headers partHeaders, InputStream content)
                            throws IOException {
                        parts
                                .add(new Part(partHeaders.getValues(HttpHeaders.CONTENT_TYPE)[0],
                                        partHeaders.getContentTransferEncoding(), content.readAllBytes()));
                    }
                });
        return parts;
    }

    private static X509Certificate theOnlyCertificateOf(Part certificatePart) throws Exception {
        Collection<X509CertificateHolder> held = new CMSSignedData(certificatePart.content())
                .getCertificates()
                .getMatches(null);
        assertThat(held).hasSize(1);
        return new JcaX509CertificateConverter().getCertificate(held.iterator().next());
    }

    /** The private key of the answer. */
    private static KeyMaterial keyMaterialOf(MockHttpServletResponse response) throws IOException {
        byte[] pkcs8 = parseMultipart(response).getFirst().content();
        return new KeyMaterial(List.of(), List.of(), List.of()).withPrivateKey(pkcs8);
    }

    /**
     * What no captured text may carry. A text carries it when it holds a verbatim form, or when, with every whitespace,
     * {@code :} and escaped line break taken out, it holds an encoding in single-line base64, or in hex in either case.
     * So a key wrapped at any width, or in hex with separators, is found too.
     *
     * @param verbatim texts matched as they are, such as a passphrase
     * @param base64 encodings in single-line base64
     * @param hex encodings in lower-case hex
     */
    private record KeyMaterial(List<String> verbatim, List<String> base64, List<String> hex) {

        KeyMaterial withVerbatim(List<String> texts) {
            return new KeyMaterial(concat(verbatim, texts), base64, hex);
        }

        /**
         * Adds an EC private key as its whole PKCS#8 encoding and as its private value alone. The base64 lines of a key
         * as sent are not matched one by one: the lines that encode only its public key show in every certificate and
         * request for that key.
         * <p>
         * The private value is matched in hex, and in base64 as three unpadded slices that start at each of its first
         * three bytes, so that one of them lines up with any base64 stream that carries the value, whatever wraps it.
         * The value is read at the length of the order of its curve.
         */
        KeyMaterial withPrivateKey(byte[] pkcs8) throws IOException {
            PrivateKeyInfo info = PrivateKeyInfo.getInstance(pkcs8);
            ASN1ObjectIdentifier curve = ASN1ObjectIdentifier
                    .getInstance(info.getPrivateKeyAlgorithm().getParameters());
            int valueLength = BigIntegers.getUnsignedByteLength(ECNamedCurveTable.getByOID(curve).getN());
            byte[] privateValue = BigIntegers
                    .asUnsignedByteArray(valueLength, ECPrivateKey.getInstance(info.parsePrivateKey()).getKey());
            int sliceLength = (valueLength - 2) / 3 * 3;
            List<String> slices = IntStream
                    .range(0, 3)
                    .mapToObj(start -> Base64
                            .getEncoder()
                            .encodeToString(Arrays.copyOfRange(privateValue, start, start + sliceLength)))
                    .toList();
            return withEncoding(pkcs8).withForms(slices, List.of(HexFormat.of().formatHex(privateValue)));
        }

        private KeyMaterial withEncoding(byte[] encoding) {
            return withForms(List.of(Base64.getEncoder().encodeToString(encoding)),
                    List.of(HexFormat.of().formatHex(encoding)));
        }

        private KeyMaterial withForms(List<String> base64Forms, List<String> hexForms) {
            return new KeyMaterial(verbatim, concat(base64, base64Forms), concat(hex, hexForms));
        }

        boolean isCarriedBy(String text) {
            String compact = text.replace("\\r", "").replace("\\n", "").replaceAll("[\\s:]", "");
            String compactLowerCase = compact.toLowerCase(Locale.ROOT);
            return verbatim.stream().anyMatch(form -> text.contains(form) || compact.contains(form))
                    || base64.stream().anyMatch(compact::contains) || hex.stream().anyMatch(compactLowerCase::contains);
        }

        private static List<String> concat(List<String> first, List<String> second) {
            List<String> all = new ArrayList<>(first);
            all.addAll(second);
            return List.copyOf(all);
        }
    }

    /** Names the kind and the indices of the texts that carry a secret, and never the text or the secret. */
    private static void assertNoneCarries(String kind, List<String> texts, KeyMaterial keyMaterial) {
        List<Integer> carrying = IntStream
                .range(0, texts.size())
                .filter(index -> keyMaterial.isCarriedBy(texts.get(index)))
                .boxed()
                .toList();
        assertThat(carrying).as("%s that carry key material, of %d", kind, texts.size()).isEmpty();
    }
}
