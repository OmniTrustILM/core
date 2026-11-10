package com.otilm.core.integration.service.acme;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.github.tomakehurst.wiremock.WireMockServer;
import com.github.tomakehurst.wiremock.client.WireMock;
import com.otilm.api.model.client.connector.v2.ConnectorVersion;
import com.otilm.api.model.core.acme.AccountStatus;
import com.otilm.api.model.core.acme.Order;
import com.otilm.api.model.core.acme.OrderStatus;
import com.otilm.api.model.core.connector.FunctionGroupCode;
import com.otilm.core.dao.entity.AuthorityInstanceReference;
import com.otilm.core.dao.entity.Connector;
import com.otilm.core.dao.entity.Connector2FunctionGroup;
import com.otilm.core.dao.entity.FunctionGroup;
import com.otilm.core.dao.entity.RaProfile;
import com.otilm.core.dao.entity.acme.AcmeAccount;
import com.otilm.core.dao.entity.acme.AcmeOrder;
import com.otilm.core.dao.entity.acme.AcmeProfile;
import com.otilm.core.dao.repository.AcmeProfileRepository;
import com.otilm.core.dao.repository.AuthorityInstanceReferenceRepository;
import com.otilm.core.dao.repository.Connector2FunctionGroupRepository;
import com.otilm.core.dao.repository.ConnectorRepository;
import com.otilm.core.dao.repository.RaProfileRepository;
import com.otilm.core.dao.repository.acme.AcmeAccountRepository;
import com.otilm.core.dao.repository.acme.AcmeNonceRepository;
import com.otilm.core.dao.repository.acme.AcmeOrderRepository;
import com.otilm.core.messaging.jms.producers.ActionProducer;
import com.otilm.core.service.acme.AcmeExternalService;
import com.otilm.core.service.acme.AcmeTestUtil;
import com.otilm.core.util.BaseSpringBootTest;
import com.otilm.core.util.LoopbackWireMock;
import com.otilm.core.util.MetaDefinitions;
import com.otilm.core.util.mockbeans.ProducerMocks;
import com.otilm.core.util.seeders.FunctionGroupSeeder;
import com.zaxxer.hikari.HikariDataSource;
import com.zaxxer.hikari.HikariPoolMXBean;
import jakarta.persistence.EntityManager;
import jakarta.persistence.EntityManagerFactory;
import java.net.URI;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicLong;
import java.util.concurrent.atomic.AtomicReference;
import javax.sql.DataSource;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
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

import static com.otilm.core.util.builders.ConnectorBuilder.aConnector;
import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.doThrow;

/**
 * ACME finalize must hold no database transaction while it submits the certificate request, or the connection its reads
 * took sits {@code idle in transaction} for the whole submission. Each finalize runs with an EntityManager bound to the
 * thread, as open-in-view binds one, and the action producer is a mock, so the queued request stays queued.
 */
@Import(ProducerMocks.class)
@TypeExcludeFilters(ProducerMocks.MockedProducersTypeExcludeFilter.class)
class AcmeFinalizeTransactionITest extends BaseSpringBootTest {

    private static final String ACME_PROFILE_NAME = "acmeFinalizeProfile";
    private static final String ACCOUNT_ID = "acmeFinalizeAccount";
    private static final String ORDER_ID = "acmeFinalizeOrder";
    private static final String DOMAIN_NAME = "finalize.example.com";
    private static final String FINALIZE_PATH = "/acme/" + ACME_PROFILE_NAME + "/order/" + ORDER_ID + "/finalize";

    private static final String IDLE_IN_TRANSACTION = """
            select count(*) from pg_stat_activity
             where datname = current_database()
               and state = 'idle in transaction'
            """;

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
    private FunctionGroupSeeder functionGroupSeeder;
    @Autowired
    private EntityManagerFactory entityManagerFactory;
    @Autowired
    private DataSource dataSource;

    private final ObjectMapper objectMapper = new ObjectMapper();
    private WireMockServer mockServer;
    private KeyPair accountKeys;

    @BeforeEach
    void seedReadyOrder() throws Exception {
        mockServer = startAuthorityConnector();
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        keyPairGenerator.initialize(2048);
        accountKeys = keyPairGenerator.generateKeyPair();

        RaProfile raProfile = seedRaProfile(seedAuthority(mockServer));
        AcmeAccount account = seedAccount(seedAcmeProfile(raProfile), raProfile);
        AcmeOrder order = new AcmeOrder();
        order.setOrderId(ORDER_ID);
        order.setStatus(OrderStatus.READY);
        order.setAcmeAccount(account);
        acmeOrderRepository.save(order);
    }

    @AfterEach
    void stopConnector() {
        mockServer.stop();
    }

    @Test
    void leavesNoConnectionIdleInTransaction_whenQueuingTheCertificateRequest() throws Exception {
        // given
        JdbcTemplate monitor = new JdbcTemplate(dataSource);
        AtomicLong idleInTransactionWhileQueuing = new AtomicLong(-1);
        doAnswer(invocation -> {
            idleInTransactionWhileQueuing.set(monitor.queryForObject(IDLE_IN_TRANSACTION, Long.class));
            return null;
        }).when(actionProducer).produceMessage(any());

        // when
        finalizeOrder();

        // then
        assertThat(idleInTransactionWhileQueuing.get()).isZero();
    }

    /**
     * The request's EntityManager keeps the connection its first read takes. A submission that holds a second one while
     * it runs makes every finalize in flight wait for two connections from the pool.
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
    void showsTheOrderProcessing_whileTheCertificateRequestIsQueued() throws Exception {
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

    // ── Helpers ───────────────────────────────────────────────────────────────

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
        EntityManager requestEntityManager = entityManagerFactory.createEntityManager();
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

    private AuthorityInstanceReference seedAuthority(WireMockServer connectorServer) {
        Connector connector = connectorRepository
                .save(aConnector()
                        .withName("acmeFinalizeConnector")
                        .withUrl(LoopbackWireMock.url(connectorServer))
                        .withVersion(ConnectorVersion.V2)
                        .withGeneratedUuid()
                        .build());

        FunctionGroup functionGroup = functionGroupSeeder.seed(FunctionGroupCode.AUTHORITY_PROVIDER, List.of());
        Connector2FunctionGroup c2fg = new Connector2FunctionGroup();
        c2fg.setConnector(connector);
        c2fg.setConnectorUuid(connector.getUuid());
        c2fg.setFunctionGroup(functionGroup);
        c2fg.setFunctionGroupUuid(functionGroup.getUuid());
        c2fg.setKinds(MetaDefinitions.serializeArrayString(List.of("ApiKey")));
        connector2FunctionGroupRepository.save(c2fg);

        AuthorityInstanceReference authorityInstance = new AuthorityInstanceReference();
        authorityInstance.setUuid(UUID.randomUUID());
        authorityInstance.setName("acmeFinalizeAuthority");
        authorityInstance.setConnector(connector);
        authorityInstance.setConnectorUuid(connector.getUuid());
        authorityInstance.setKind("ApiKey");
        authorityInstance.setAuthorityInstanceUuid("1l");
        return authorityInstanceReferenceRepository.save(authorityInstance);
    }

    private RaProfile seedRaProfile(AuthorityInstanceReference authorityInstance) {
        RaProfile raProfile = new RaProfile();
        raProfile.setName("acmeFinalizeRaProfile");
        raProfile.setEnabled(true);
        raProfile.setAuthorityInstanceReference(authorityInstance);
        raProfile.setAuthorityInstanceReferenceUuid(authorityInstance.getUuid());
        return raProfileRepository.save(raProfile);
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
