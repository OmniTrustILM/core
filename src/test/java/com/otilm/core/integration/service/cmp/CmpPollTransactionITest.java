package com.otilm.core.integration.service.cmp;

import com.github.tomakehurst.wiremock.WireMockServer;
import com.github.tomakehurst.wiremock.client.WireMock;
import com.otilm.api.model.client.connector.v2.ConnectorVersion;
import com.otilm.api.model.core.certificate.CertificateState;
import com.otilm.api.model.core.certificate.CertificateValidationStatus;
import com.otilm.api.model.core.cmp.CmpProfileVariant;
import com.otilm.api.model.core.cmp.ProtectionMethod;
import com.otilm.api.model.core.connector.ConnectorStatus;
import com.otilm.api.model.core.connector.FunctionGroupCode;
import com.otilm.core.dao.entity.AuthorityInstanceReference;
import com.otilm.core.dao.entity.Certificate;
import com.otilm.core.dao.entity.CertificateContent;
import com.otilm.core.dao.entity.Connector;
import com.otilm.core.dao.entity.Connector2FunctionGroup;
import com.otilm.core.dao.entity.FunctionGroup;
import com.otilm.core.dao.entity.RaProfile;
import com.otilm.core.dao.entity.cmp.CmpProfile;
import com.otilm.core.dao.repository.AuthorityInstanceReferenceRepository;
import com.otilm.core.dao.repository.CertificateContentRepository;
import com.otilm.core.dao.repository.CertificateRepository;
import com.otilm.core.dao.repository.Connector2FunctionGroupRepository;
import com.otilm.core.dao.repository.ConnectorRepository;
import com.otilm.core.dao.repository.FunctionGroupRepository;
import com.otilm.core.dao.repository.RaProfileRepository;
import com.otilm.core.dao.repository.cmp.CmpProfileRepository;
import com.otilm.core.messaging.jms.producers.ActionProducer;
import com.otilm.core.messaging.model.ActionMessage;
import com.otilm.core.service.cmp.CmpEntityUtil;
import com.otilm.core.service.cmp.CmpExternalService;
import com.otilm.core.service.cmp.CmpTestUtil;
import com.otilm.core.service.cmp.message.handler.PollFeature;
import com.otilm.core.util.BaseSpringBootTest;
import com.otilm.core.util.CertificateUtil;
import com.otilm.core.util.LoopbackWireMock;
import com.otilm.core.util.MetaDefinitions;
import com.otilm.core.util.mockbeans.ProducerMocks;
import jakarta.persistence.EntityManager;
import jakarta.persistence.EntityManagerFactory;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.UUID;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicLong;
import java.util.function.Consumer;
import javax.sql.DataSource;
import org.bouncycastle.asn1.cmp.CertRepMessage;
import org.bouncycastle.asn1.cmp.CertResponse;
import org.bouncycastle.asn1.cmp.PKIBody;
import org.bouncycastle.asn1.cmp.PKIFailureInfo;
import org.bouncycastle.asn1.cmp.PKIMessage;
import org.bouncycastle.asn1.cmp.PKIStatus;
import org.bouncycastle.asn1.cmp.PKIStatusInfo;
import org.bouncycastle.asn1.cmp.RevRepContent;
import org.bouncycastle.cert.X509CertificateHolder;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.test.context.filter.annotation.TypeExcludeFilters;
import org.springframework.context.annotation.Import;
import org.springframework.http.ResponseEntity;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.orm.jpa.EntityManagerHolder;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.support.TransactionSynchronizationManager;
import org.springframework.transaction.support.TransactionTemplate;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.doAnswer;

/**
 * A CMP request waits for its certificate in a poll loop. The loop must not hold a database transaction: the connection
 * would sit {@code idle in transaction} for the whole budget, beside the one the submission takes. Each request runs
 * with an EntityManager bound to the thread, as open-in-view binds one in production, and the action producer is a
 * mock, so a certificate stays where the submission left it until a test moves it on.
 */
@Import(ProducerMocks.class)
@TypeExcludeFilters(ProducerMocks.MockedProducersTypeExcludeFilter.class)
class CmpPollTransactionITest extends BaseSpringBootTest {

    private static final String PROFILE_NAME = "cmpPollProfile";
    private static final String SHARED_SECRET = "cmp-poll-shared-secret";
    private static final String TRANSACTION_ID = "0102030405060708";
    private static final int POLL_BUDGET_SECONDS = 2;
    private static final Duration COMPLETION_DELAY = Duration.ofMillis(1_200);
    private static final BigInteger ISSUED_SERIAL = BigInteger.valueOf(0x2720L);

    /**
     * Connections that have been {@code idle in transaction} for longer than a short statement gap. The poll loop
     * sleeps a full second between reads, so a transaction held across it is caught on every sleep.
     */
    private static final String HELD_IDLE_TRANSACTIONS = """
            select count(*) from pg_stat_activity
             where datname = current_database()
               and state = 'idle in transaction'
               and state_change < clock_timestamp() - interval '500 milliseconds'
            """;

    @Autowired
    private CmpExternalService cmpService;
    @Autowired
    private PollFeature pollFeature;
    @Autowired
    private ActionProducer actionProducer;
    @Autowired
    private CmpProfileRepository cmpProfileRepository;
    @Autowired
    private RaProfileRepository raProfileRepository;
    @Autowired
    private CertificateRepository certificateRepository;
    @Autowired
    private CertificateContentRepository certificateContentRepository;
    @Autowired
    private ConnectorRepository connectorRepository;
    @Autowired
    private AuthorityInstanceReferenceRepository authorityInstanceReferenceRepository;
    @Autowired
    private FunctionGroupRepository functionGroupRepository;
    @Autowired
    private Connector2FunctionGroupRepository connector2FunctionGroupRepository;
    @Autowired
    private EntityManagerFactory entityManagerFactory;
    @Autowired
    private PlatformTransactionManager transactionManager;
    @Autowired
    private DataSource dataSource;
    @Value("${cmp.protocol.poll.feature.timeout}")
    private Integer configuredPollBudgetSeconds;

    private WireMockServer mockServer;
    private RaProfile raProfile;
    private final List<CompletableFuture<Void>> completions = new ArrayList<>();

    @BeforeEach
    void seedCmpProfileWithShortPollBudget() {
        mockServer = CmpTestUtil.createIssuingPlatform();
        stubRevokeAttributes(mockServer);
        raProfile = raProfileRepository.saveAndFlush(CmpEntityUtil.createRaProfile(seedAuthority(mockServer)));

        CmpProfile cmpProfile = new CmpProfile();
        cmpProfile.setName(PROFILE_NAME);
        cmpProfile.setEnabled(true);
        cmpProfile.setVariant(CmpProfileVariant.V2);
        cmpProfile.setRequestProtectionMethod(ProtectionMethod.SHARED_SECRET);
        cmpProfile.setResponseProtectionMethod(ProtectionMethod.SHARED_SECRET);
        cmpProfile.setSharedSecret(SHARED_SECRET);
        cmpProfile.setRaProfile(raProfile);
        cmpProfileRepository.saveAndFlush(cmpProfile);

        pollFeature.setPollFeatureTimeout(POLL_BUDGET_SECONDS);
    }

    @AfterEach
    void restorePollBudgetAndStopConnector() {
        pollFeature.setPollFeatureTimeout(configuredPollBudgetSeconds);
        mockServer.stop();
        completions.forEach(CompletableFuture::join);
    }

    @Test
    void leavesNoConnectionIdleInTransaction_whilePollingAnIssue() throws Exception {
        // given — nothing claims the queued request, so the poll runs its whole budget
        IdleTransactionWatch watch = IdleTransactionWatch.start(new JdbcTemplate(dataSource));

        // when
        post(irMessage());

        // then
        assertThat(watch.stop()).as("connections held idle in transaction while polling").isZero();
    }

    @Test
    void answersWithTheIssuedCertificate_whenIssuanceCompletesWhilePolling() throws Exception {
        // given
        X509CertificateHolder issued = issuedCertificate(ISSUED_SERIAL);
        completeQueuedActionsWith(certificateUuid -> markIssued(certificateUuid, issued));

        // when
        PKIMessage response = post(irMessage());

        // then
        CertResponse certResponse = singleCertResponse(response);
        assertThat(certResponse.getStatus().getStatus().intValue()).isEqualTo(PKIStatus.GRANTED);
        BigInteger returnedSerial = certResponse
                .getCertifiedKeyPair()
                .getCertOrEncCert()
                .getCertificate()
                .getX509v3PKCert()
                .getSerialNumber()
                .getValue();
        assertThat(returnedSerial).isEqualTo(ISSUED_SERIAL);
    }

    @Test
    void answersWithARejection_whenIssuanceFailsWhilePolling() throws Exception {
        // given
        completeQueuedActionsWith(certificateUuid -> moveTo(certificateUuid, CertificateState.FAILED));

        // when
        PKIMessage response = post(irMessage());

        // then
        PKIStatusInfo status = singleCertResponse(response).getStatus();
        assertThat(status.getStatus().intValue()).isEqualTo(PKIStatus.REJECTION);
        assertThat(status.getFailInfo().intValue()).isEqualTo(PKIFailureInfo.systemFailure);
        assertThat(status.getStatusString().getStringAtUTF8(0).getString()).contains("diverted to FAILED");
    }

    @Test
    void leavesNoConnectionIdleInTransaction_whilePollingARevocation() throws Exception {
        // given — nothing claims the queued revocation, so the poll runs its whole budget
        Certificate certificate = seedIssuedCertificate(ISSUED_SERIAL);
        IdleTransactionWatch watch = IdleTransactionWatch.start(new JdbcTemplate(dataSource));

        // when
        post(rrMessage(certificate));

        // then
        assertThat(watch.stop()).as("connections held idle in transaction while polling").isZero();
    }

    @Test
    void answersWithRevocationNotification_whenRevocationCompletesWhilePolling() throws Exception {
        // given
        Certificate certificate = seedIssuedCertificate(ISSUED_SERIAL);
        completeQueuedActionsWith(certificateUuid -> moveTo(certificateUuid, CertificateState.REVOKED));

        // when
        PKIMessage response = post(rrMessage(certificate));

        // then
        assertThat(response.getBody().getType()).isEqualTo(PKIBody.TYPE_REVOCATION_REP);
        PKIStatusInfo status = ((RevRepContent) response.getBody().getContent()).getStatus()[0];
        assertThat(status.getStatus().intValue()).isEqualTo(PKIStatus.REVOCATION_NOTIFICATION);
    }

    // ── Helpers ───────────────────────────────────────────────────────────────

    /**
     * Posts {@code request} as one HTTP request does: with the servlet request in context and an EntityManager bound to
     * the thread from start to end.
     */
    private PKIMessage post(PKIMessage request) throws Exception {
        MockHttpServletRequest servletRequest = new MockHttpServletRequest("POST", "/v1/protocols/cmp/" + PROFILE_NAME);
        RequestContextHolder.setRequestAttributes(new ServletRequestAttributes(servletRequest));
        EntityManager requestEntityManager = entityManagerFactory.createEntityManager();
        TransactionSynchronizationManager
                .bindResource(entityManagerFactory, new EntityManagerHolder(requestEntityManager));
        try {
            ResponseEntity<byte[]> response = cmpService.handlePost(PROFILE_NAME, request.getEncoded());
            return PKIMessage.getInstance(response.getBody());
        } finally {
            TransactionSynchronizationManager.unbindResource(entityManagerFactory);
            requestEntityManager.close();
            RequestContextHolder.resetRequestAttributes();
        }
    }

    /** Lets the actions listener's work land a while after each queued action, as a backlog would. */
    private void completeQueuedActionsWith(Consumer<UUID> completion) {
        doAnswer(invocation -> {
            ActionMessage queued = invocation.getArgument(0);
            completions
                    .add(CompletableFuture
                            .runAsync(() -> completion.accept(queued.getResourceUuid()), CompletableFuture
                                    .delayedExecutor(COMPLETION_DELAY.toMillis(), TimeUnit.MILLISECONDS)));
            return null;
        }).when(actionProducer).produceMessage(any());
    }

    private void markIssued(UUID certificateUuid, X509CertificateHolder issued) {
        new TransactionTemplate(transactionManager).executeWithoutResult(status -> {
            CertificateContent content = certificateContentRepository.save(contentOf(issued));
            Certificate certificate = certificateRepository.findByUuid(certificateUuid).orElseThrow();
            certificate.setCertificateContent(content);
            certificate.setFingerprint(content.getFingerprint());
            certificate.setSerialNumber(issued.getSerialNumber().toString(16));
            certificate.setValidationStatus(CertificateValidationStatus.VALID);
            certificate.setState(CertificateState.ISSUED);
        });
    }

    private void moveTo(UUID certificateUuid, CertificateState state) {
        new TransactionTemplate(transactionManager)
                .executeWithoutResult(
                        status -> certificateRepository.findByUuid(certificateUuid).orElseThrow().setState(state));
    }

    private Certificate seedIssuedCertificate(BigInteger serialNumber) {
        Certificate certificate = CmpEntityUtil.createCertificate(serialNumber, CertificateState.ISSUED, null);
        certificate.setRaProfile(raProfile);
        certificate.setRaProfileUuid(raProfile.getUuid());
        return certificateRepository.saveAndFlush(certificate);
    }

    private AuthorityInstanceReference seedAuthority(WireMockServer connectorServer) {
        Connector connector = new Connector();
        connector.setName("cmpPollConnector");
        connector.setUrl(LoopbackWireMock.url(connectorServer));
        connector.setVersion(ConnectorVersion.V1);
        connector.setStatus(ConnectorStatus.CONNECTED);
        connector = connectorRepository.save(connector);

        FunctionGroup functionGroup = new FunctionGroup();
        functionGroup.setCode(FunctionGroupCode.AUTHORITY_PROVIDER);
        functionGroup.setName(FunctionGroupCode.AUTHORITY_PROVIDER.getCode());
        functionGroupRepository.save(functionGroup);

        Connector2FunctionGroup c2fg = new Connector2FunctionGroup();
        c2fg.setConnector(connector);
        c2fg.setConnectorUuid(connector.getUuid());
        c2fg.setFunctionGroup(functionGroup);
        c2fg.setFunctionGroupUuid(functionGroup.getUuid());
        c2fg.setKinds(MetaDefinitions.serializeArrayString(List.of("ApiKey")));
        connector2FunctionGroupRepository.save(c2fg);
        connector.getFunctionGroups().add(c2fg);
        connector.setVersion(ConnectorVersion.V2);
        connectorRepository.save(connector);

        AuthorityInstanceReference authorityInstance = new AuthorityInstanceReference();
        authorityInstance.setUuid(UUID.randomUUID());
        authorityInstance.setName("cmpPollAuthority");
        authorityInstance.setConnector(connector);
        authorityInstance.setConnectorUuid(connector.getUuid());
        authorityInstance.setKind("sample");
        authorityInstance.setAuthorityInstanceUuid("1l");
        return authorityInstanceReferenceRepository.save(authorityInstance);
    }

    private static void stubRevokeAttributes(WireMockServer connectorServer) {
        connectorServer
                .stubFor(WireMock
                        .get(WireMock
                                .urlPathMatching(
                                        "/v2/authorityProvider/authorities/[^/]+/certificates/revoke/attributes"))
                        .willReturn(WireMock.okJson("[]")));
        connectorServer
                .stubFor(WireMock
                        .post(WireMock
                                .urlPathMatching(
                                        "/v2/authorityProvider/authorities/[^/]+/certificates/revoke/attributes/validate"))
                        .willReturn(WireMock.okJson("true")));
    }

    private static PKIMessage irMessage() throws Exception {
        KeyPair keyPair = CmpTestUtil.generateKeyPairEC();
        return macProtected(CmpTestUtil.createCrmfBody(keyPair, 0L, PKIBody.TYPE_INIT_REQ));
    }

    private static PKIMessage rrMessage(Certificate certificate) throws Exception {
        return macProtected(CmpTestUtil.createRevocationBody(new BigInteger(certificate.getSerialNumber(), 16)));
    }

    private static PKIMessage macProtected(PKIBody body) throws Exception {
        byte[] senderKid = PROFILE_NAME.getBytes(StandardCharsets.UTF_8);
        return CmpTestUtil
                .createMacBasedMessageWithSenderKid(TRANSACTION_ID, SHARED_SECRET, body, senderKid)
                .toASN1Structure();
    }

    private static X509CertificateHolder issuedCertificate(BigInteger serialNumber) throws Exception {
        KeyPair keyPair = CmpTestUtil.generateKeyPairEC();
        return CmpTestUtil.makeV3Certificate(serialNumber, keyPair, "CN=user", keyPair, "CN=user");
    }

    private static CertificateContent contentOf(X509CertificateHolder certificate) {
        try {
            byte[] encoded = certificate.getEncoded();
            return CmpEntityUtil
                    .createCertContent(CertificateUtil.getThumbprint(encoded),
                            Base64.getEncoder().encodeToString(encoded));
        } catch (Exception e) {
            throw new IllegalStateException("cannot encode the issued certificate", e);
        }
    }

    private static CertResponse singleCertResponse(PKIMessage response) {
        assertThat(response.getBody().getType()).isEqualTo(PKIBody.TYPE_INIT_REP);
        return ((CertRepMessage) response.getBody().getContent()).getResponse()[0];
    }

    /**
     * Samples {@code pg_stat_activity} every 100 ms on its own connection and keeps the highest count of connections
     * held idle in transaction.
     */
    private static final class IdleTransactionWatch {

        private final ScheduledExecutorService sampler = Executors.newSingleThreadScheduledExecutor();
        private final AtomicLong highest = new AtomicLong();

        static IdleTransactionWatch start(JdbcTemplate jdbcTemplate) {
            IdleTransactionWatch watch = new IdleTransactionWatch();
            watch.sampler.scheduleAtFixedRate(() -> {
                Long held = jdbcTemplate.queryForObject(HELD_IDLE_TRANSACTIONS, Long.class);
                watch.highest.accumulateAndGet(held == null ? 0L : held, Math::max);
            }, 0L, 100L, TimeUnit.MILLISECONDS);
            return watch;
        }

        long stop() throws InterruptedException {
            sampler.shutdownNow();
            sampler.awaitTermination(5, TimeUnit.SECONDS);
            return highest.get();
        }
    }
}
