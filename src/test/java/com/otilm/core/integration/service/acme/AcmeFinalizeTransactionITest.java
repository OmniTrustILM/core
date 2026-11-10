package com.otilm.core.integration.service.acme;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.github.tomakehurst.wiremock.WireMockServer;
import com.github.tomakehurst.wiremock.client.WireMock;
import com.otilm.api.exception.AcmeProblemDocumentException;
import com.otilm.api.model.core.acme.AccountStatus;
import com.otilm.api.model.core.acme.Order;
import com.otilm.api.model.core.acme.OrderStatus;
import com.otilm.api.model.core.acme.Problem;
import com.otilm.core.dao.entity.RaProfile;
import com.otilm.core.dao.entity.acme.AcmeAccount;
import com.otilm.core.dao.entity.acme.AcmeOrder;
import com.otilm.core.dao.entity.acme.AcmeProfile;
import com.otilm.core.dao.repository.AcmeProfileRepository;
import com.otilm.core.dao.repository.AuthorityInstanceReferenceRepository;
import com.otilm.core.dao.repository.Connector2FunctionGroupRepository;
import com.otilm.core.dao.repository.ConnectorInterfaceRepository;
import com.otilm.core.dao.repository.ConnectorRepository;
import com.otilm.core.dao.repository.FunctionGroupRepository;
import com.otilm.core.dao.repository.RaProfileRepository;
import com.otilm.core.dao.repository.acme.AcmeAccountRepository;
import com.otilm.core.dao.repository.acme.AcmeNonceRepository;
import com.otilm.core.dao.repository.acme.AcmeOrderRepository;
import com.otilm.core.messaging.jms.producers.ActionProducer;
import com.otilm.core.service.acme.AcmeExternalService;
import com.otilm.core.service.acme.AcmeTestUtil;
import com.otilm.core.service.acme.identifier.AcmeCsrIdentifiers;
import com.otilm.core.service.writer.AcmeChallengeWriter;
import com.otilm.core.util.BaseSpringBootTest;
import com.otilm.core.util.LoopbackWireMock;
import com.otilm.core.util.builders.AuthorityFixtures;
import com.otilm.core.util.mockbeans.ProducerMocks;
import com.zaxxer.hikari.HikariDataSource;
import com.zaxxer.hikari.HikariPoolMXBean;
import jakarta.persistence.EntityManager;
import jakarta.persistence.EntityManagerFactory;
import java.net.URI;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.sql.ResultSet;
import java.sql.Statement;
import java.util.Base64;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;
import javax.sql.DataSource;
import org.assertj.core.api.ThrowableAssert.ThrowingCallable;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.hibernate.Session;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.MockedStatic;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.filter.annotation.TypeExcludeFilters;
import org.springframework.context.annotation.Import;
import org.springframework.http.ResponseEntity;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.orm.jpa.EntityManagerHolder;
import org.springframework.transaction.support.TransactionSynchronizationManager;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.CALLS_REAL_METHODS;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mockStatic;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;

/**
 * ACME finalize must hold no database transaction while it submits the certificate request, or the connection its reads
 * took sits {@code idle in transaction} for the whole submission, and must still write the order only under its lock,
 * so that a second finalize submits nothing and a concurrent account deactivation is not overwritten. Each finalize
 * runs with an EntityManager bound to the thread, as open-in-view binds one, and the action producer is a mock, so the
 * queued request stays queued.
 */
@Import(ProducerMocks.class)
@TypeExcludeFilters(ProducerMocks.MockedProducersTypeExcludeFilter.class)
class AcmeFinalizeTransactionITest extends BaseSpringBootTest {

    private static final String ACME_PROFILE_NAME = "acmeFinalizeProfile";
    private static final String ACCOUNT_ID = "acmeFinalizeAccount";
    private static final String ORDER_ID = "acmeFinalizeOrder";
    private static final String DOMAIN_NAME = "finalize.example.com";
    private static final String FINALIZE_PATH = "/acme/" + ACME_PROFILE_NAME + "/order/" + ORDER_ID + "/finalize";

    private static final String CONNECTION_STATE = "select state from pg_stat_activity where pid = ?";

    @Autowired
    private AcmeExternalService acmeService;
    @Autowired
    private ActionProducer actionProducer;
    @Autowired
    private ConnectorRepository connectorRepository;
    @Autowired
    private Connector2FunctionGroupRepository connector2FunctionGroupRepository;
    @Autowired
    private AuthorityInstanceReferenceRepository authorityInstanceReferenceRepository;
    @Autowired
    private RaProfileRepository raProfileRepository;
    @Autowired
    private AcmeProfileRepository acmeProfileRepository;
    @Autowired
    private AcmeAccountRepository acmeAccountRepository;
    @Autowired
    private AcmeOrderRepository acmeOrderRepository;
    @Autowired
    private AcmeNonceRepository acmeNonceRepository;
    @Autowired
    private AcmeChallengeWriter acmeChallengeWriter;
    @Autowired
    private FunctionGroupRepository functionGroupRepository;
    @Autowired
    private ConnectorInterfaceRepository connectorInterfaceRepository;
    @Autowired
    private EntityManagerFactory entityManagerFactory;
    @Autowired
    private DataSource dataSource;

    private final ObjectMapper objectMapper = new ObjectMapper();
    private WireMockServer mockServer;
    private KeyPair accountKeys;
    private UUID orderUuid;
    private EntityManager requestEntityManager;

    @BeforeEach
    void seedReadyOrder() throws Exception {
        mockServer = startAuthorityConnector();
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        keyPairGenerator.initialize(2048);
        accountKeys = keyPairGenerator.generateKeyPair();

        RaProfile raProfile = AuthorityFixtures
                .v2Authority(new AuthorityFixtures.Repos(connectorRepository, functionGroupRepository,
                        connector2FunctionGroupRepository, authorityInstanceReferenceRepository, raProfileRepository,
                        connectorInterfaceRepository), mockServer, "ApiKey")
                .raProfile();
        AcmeAccount account = seedAccount(seedAcmeProfile(raProfile), raProfile);
        AcmeOrder order = new AcmeOrder();
        order.setOrderId(ORDER_ID);
        order.setStatus(OrderStatus.READY);
        order.setAcmeAccount(account);
        orderUuid = acmeOrderRepository.save(order).getUuid();
    }

    @AfterEach
    void stopConnector() {
        mockServer.stop();
    }

    /**
     * Only the request's own connection is sampled: the test database is shared with every cached context, whose
     * scheduled jobs may be between two statements of a transaction at any moment.
     */
    @Test
    void keepsTheRequestsConnectionOutOfATransaction_whenQueuingTheCertificateRequest() throws Exception {
        // given
        JdbcTemplate monitor = new JdbcTemplate(dataSource);
        AtomicReference<String> requestConnectionState = new AtomicReference<>();
        doAnswer(invocation -> {
            requestConnectionState
                    .set(monitor.queryForObject(CONNECTION_STATE, String.class, requestEntityManagerBackend()));
            return null;
        }).when(actionProducer).produceMessage(any());

        // when
        finalizeOrder();

        // then
        assertThat(requestConnectionState.get()).isEqualTo("idle");
    }

    /**
     * The request's EntityManager keeps the connection its first read takes, and nothing else may still hold one once
     * the request is queued. The submission's own short transactions borrow a second connection while they run, which
     * this does not see.
     */
    @Test
    void holdsOnlyTheRequestsConnection_whenQueuingTheCertificateRequest() throws Exception {
        // given
        HikariPoolMXBean pool = dataSource.unwrap(HikariDataSource.class).getHikariPoolMXBean();
        int activeBeforeTheRequest = pool.getActiveConnections();
        AtomicInteger activeWhileQueuing = new AtomicInteger(-1);
        doAnswer(invocation -> {
            activeWhileQueuing.set(pool.getActiveConnections());
            return null;
        }).when(actionProducer).produceMessage(any());

        // when
        finalizeOrder();

        // then
        assertThat(activeWhileQueuing.get()).isEqualTo(activeBeforeTheRequest + 1);
    }

    @Test
    void showsTheOrderProcessing_whenQueuingTheCertificateRequest() throws Exception {
        // given
        AtomicReference<OrderStatus> statusSeenByAnotherClient = new AtomicReference<>();
        doAnswer(invocation -> {
            statusSeenByAnotherClient.set(readCommittedOrderStatus());
            return null;
        }).when(actionProducer).produceMessage(any());

        // when
        finalizeOrder();

        // then
        assertThat(statusSeenByAnotherClient.get()).isEqualTo(OrderStatus.PROCESSING);
    }

    @Test
    void answersProcessing_whenTheCertificateRequestIsQueued() throws Exception {
        // given — the ready order every test seeds

        // when
        ResponseEntity<Order> response = finalizeOrder();

        // then
        assertThat(response.getBody().getStatus()).isEqualTo(OrderStatus.PROCESSING);
        AcmeOrder stored = acmeOrderRepository.findByOrderId(ORDER_ID).orElseThrow();
        assertThat(stored.getStatus()).isEqualTo(OrderStatus.PROCESSING);
        assertThat(stored.getCertificateReferenceUuid()).isNotNull();
    }

    @Test
    void answersInvalid_whenQueuingTheCertificateRequestFails() throws Exception {
        // given
        doThrow(new IllegalStateException("queue unavailable")).when(actionProducer).produceMessage(any());

        // when
        ResponseEntity<Order> response = finalizeOrder();

        // then
        assertThat(response.getBody().getStatus()).isEqualTo(OrderStatus.INVALID);
        assertThat(acmeOrderRepository.findByOrderId(ORDER_ID).orElseThrow().getStatus())
                .isEqualTo(OrderStatus.INVALID);
        assertThat(acmeAccountRepository.findByAccountId(ACCOUNT_ID).orElseThrow().getFailedOrders()).isEqualTo(1);
    }

    @Test
    void keepsTheOrderInvalid_whenADeactivationClosesItDuringTheSubmission() throws Exception {
        // given
        doAnswer(invocation -> {
            deactivateOrderOnAnotherThread();
            return null;
        }).when(actionProducer).produceMessage(any());

        // when
        ResponseEntity<Order> response = finalizeOrder();

        // then
        assertThat(response.getBody().getStatus()).isEqualTo(OrderStatus.INVALID);
        AcmeOrder stored = acmeOrderRepository.findByOrderId(ORDER_ID).orElseThrow();
        assertThat(stored.getStatus()).isEqualTo(OrderStatus.INVALID);
        assertThat(stored.getCertificateReferenceUuid()).isNotNull();
    }

    @Test
    void countsNoFailure_whenADeactivationClosedTheOrderBeforeTheSubmissionFailed() throws Exception {
        // given
        doAnswer(invocation -> {
            deactivateOrderOnAnotherThread();
            throw new IllegalStateException("queue unavailable");
        }).when(actionProducer).produceMessage(any());

        // when
        finalizeOrder();

        // then
        assertThat(acmeOrderRepository.findByOrderId(ORDER_ID).orElseThrow().getStatus())
                .isEqualTo(OrderStatus.INVALID);
        assertThat(acmeAccountRepository.findByAccountId(ACCOUNT_ID).orElseThrow().getFailedOrders()).isZero();
    }

    /**
     * Another finalize request claims the order after this one found it ready. Reading the CSR's identifiers is the
     * hook: finalize does it between the ready check and its own claim.
     */
    @Test
    void answersOrderNotReady_whenAnotherFinalizeClaimsTheOrderFirst() {
        try (MockedStatic<AcmeCsrIdentifiers> csrIdentifiers = mockStatic(AcmeCsrIdentifiers.class,
                CALLS_REAL_METHODS)) {
            // given
            csrIdentifiers.when(() -> AcmeCsrIdentifiers.of(any())).thenAnswer(invocation -> {
                claimOrderOnAnotherThread();
                return invocation.callRealMethod();
            });

            // when
            ThrowingCallable finalize = this::finalizeOrder;

            // then
            assertThatThrownBy(finalize)
                    .isInstanceOfSatisfying(AcmeProblemDocumentException.class,
                            exception -> assertThat(exception.getProblemDocument().getType())
                                    .isEqualTo(Problem.ORDER_NOT_READY.getType()));
            verify(actionProducer, never()).produceMessage(any());
        }
    }

    @Test
    void refusesTheClaim_whenAnotherFinalizeClaimedTheOrderFirst() {
        // given
        boolean firstClaim = acmeChallengeWriter.claimForFinalize(orderUuid);

        // when
        boolean secondClaim = acmeChallengeWriter.claimForFinalize(orderUuid);

        // then
        assertThat(firstClaim).isTrue();
        assertThat(secondClaim).isFalse();
        assertThat(readCommittedOrderStatus()).isEqualTo(OrderStatus.PROCESSING);
    }

    // ── Helpers ───────────────────────────────────────────────────────────────

    /**
     * Closes the order as a concurrent account deactivation does, in a request of its own, but without the failed-order
     * count the deactivation adds afterwards, so the account's count shows only what finalize adds.
     */
    private void deactivateOrderOnAnotherThread() {
        CompletableFuture.runAsync(() -> acmeChallengeWriter.deactivateOrder(orderUuid)).join();
    }

    /** Claims the order as a concurrent finalize request does, in a request of its own. */
    private void claimOrderOnAnotherThread() {
        CompletableFuture.runAsync(() -> acmeChallengeWriter.claimForFinalize(orderUuid)).join();
    }

    /**
     * Sends the finalize request as one HTTP request does: with the servlet request in context and an EntityManager
     * bound to the thread from start to end.
     */
    private ResponseEntity<Order> finalizeOrder() throws Exception {
        PKCS10CertificationRequest csr = AcmeTestUtil
                .createCsr(KeyPairGenerator.getInstance("RSA").generateKeyPair(), DOMAIN_NAME);
        Map<String, Object> payload = Map
                .of("csr", Base64.getUrlEncoder().withoutPadding().encodeToString(csr.getEncoded()));
        String jws = AcmeTestUtil
                .createJwsRequest(objectMapper, accountKeys, acmeNonceRepository, payload, FINALIZE_PATH, ACCOUNT_ID,
                        ACME_PROFILE_NAME);

        RequestContextHolder
                .setRequestAttributes(new ServletRequestAttributes(
                        new MockHttpServletRequest("POST", "/v1/protocols" + FINALIZE_PATH)));
        requestEntityManager = entityManagerFactory.createEntityManager();
        TransactionSynchronizationManager
                .bindResource(entityManagerFactory, new EntityManagerHolder(requestEntityManager));
        try {
            return acmeService.finalizeOrder(ACME_PROFILE_NAME, ORDER_ID, jws, new URI(FINALIZE_PATH), false);
        } finally {
            TransactionSynchronizationManager.unbindResource(entityManagerFactory);
            requestEntityManager.close();
            RequestContextHolder.resetRequestAttributes();
        }
    }

    private long requestEntityManagerBackend() {
        return requestEntityManager.unwrap(Session.class).doReturningWork(connection -> {
            try (Statement statement = connection.createStatement();
                    ResultSet backend = statement.executeQuery("select pg_backend_pid()")) {
                backend.next();
                return backend.getLong(1);
            }
        });
    }

    /** Reads the order on an EntityManager of its own, so it sees only what has been committed. */
    private OrderStatus readCommittedOrderStatus() {
        EntityManager observer = entityManagerFactory.createEntityManager();
        try {
            return observer
                    .createQuery("select o.status from AcmeOrder o where o.orderId = :orderId", OrderStatus.class)
                    .setParameter("orderId", ORDER_ID)
                    .getSingleResult();
        } finally {
            observer.close();
        }
    }

    private static WireMockServer startAuthorityConnector() {
        WireMockServer connectorServer = LoopbackWireMock.start();
        connectorServer
                .stubFor(WireMock
                        .post(WireMock
                                .urlPathMatching(
                                        "/v2/authorityProvider/authorities/[^/]+/certificates/issue/attributes/validate"))
                        .willReturn(WireMock.okJson("true")));
        connectorServer
                .stubFor(WireMock
                        .get(WireMock
                                .urlPathMatching(
                                        "/v2/authorityProvider/authorities/[^/]+/certificates/issue/attributes"))
                        .willReturn(WireMock.okJson("[]")));
        return connectorServer;
    }

    private AcmeProfile seedAcmeProfile(RaProfile raProfile) {
        AcmeProfile acmeProfile = new AcmeProfile();
        acmeProfile.setName(ACME_PROFILE_NAME);
        acmeProfile.setRaProfile(raProfile);
        acmeProfile.setEnabled(true);
        acmeProfile.setValidity(30);
        acmeProfile.setRetryInterval(30);
        acmeProfile.setDnsResolverIp("localhost");
        acmeProfile.setDnsResolverPort("53");
        acmeProfile = acmeProfileRepository.save(acmeProfile);
        raProfile.setAcmeProfile(acmeProfile);
        raProfileRepository.save(raProfile);
        return acmeProfile;
    }

    private AcmeAccount seedAccount(AcmeProfile acmeProfile, RaProfile raProfile) {
        AcmeAccount account = new AcmeAccount();
        account.setAccountId(ACCOUNT_ID);
        account.setStatus(AccountStatus.VALID);
        account.setEnabled(true);
        account.setTermsOfServiceAgreed(true);
        account.setAcmeProfile(acmeProfile);
        account.setRaProfile(raProfile);
        account.setPublicKey(Base64.getEncoder().encodeToString(accountKeys.getPublic().getEncoded()));
        return acmeAccountRepository.save(account);
    }
}
