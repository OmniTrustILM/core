package com.otilm.core.integration.service;

import com.otilm.api.model.client.connector.v2.ConnectorInterface;
import com.otilm.api.model.client.connector.v2.ConnectorVersion;
import com.otilm.api.model.client.cryptography.key.KeyRequestType;
import com.otilm.api.model.common.enums.cryptography.KeyAlgorithm;
import com.otilm.api.model.connector.cryptography.enums.TokenInstanceStatus;
import com.otilm.api.model.core.connector.ConnectorStatus;
import com.otilm.core.dao.entity.Connector;
import com.otilm.core.dao.entity.ConnectorInterfaceEntity;
import com.otilm.core.dao.entity.TokenInstanceReference;
import com.otilm.core.dao.entity.TokenProfile;
import com.otilm.core.dao.repository.ConnectorInterfaceRepository;
import com.otilm.core.dao.repository.ConnectorRepository;
import com.otilm.core.dao.repository.TokenInstanceReferenceRepository;
import com.otilm.core.dao.repository.TokenProfileRepository;
import com.otilm.core.model.crypto.TokenProfileFullModel;
import com.otilm.core.model.crypto.TransferableKeyType;
import com.otilm.core.service.writer.KeyTransferCapabilityWriter;
import com.otilm.core.util.BaseSpringBootTest;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import org.awaitility.Awaitility;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.support.TransactionTemplate;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Committed transactions on separate threads, as in production: an answer asked for before a change must never be
 * recorded after it, whichever way the two writes meet on the profile's row lock.
 */
class KeyTransferCapabilityWriterConcurrencyITest extends BaseSpringBootTest {

    private static final long TIMEOUT_SECONDS = 30;

    private static final List<TransferableKeyType> RSA_KEY_PAIRS = List
            .of(new TransferableKeyType(KeyRequestType.KEY_PAIR, Set.of(KeyAlgorithm.RSA)));

    @Autowired
    private KeyTransferCapabilityWriter keyTransferCapabilityWriter;

    @Autowired
    private PlatformTransactionManager transactionManager;

    @Autowired
    private JdbcTemplate jdbcTemplate;

    @Autowired
    private ConnectorRepository connectorRepository;

    @Autowired
    private ConnectorInterfaceRepository connectorInterfaceRepository;

    @Autowired
    private TokenInstanceReferenceRepository tokenInstanceReferenceRepository;

    @Autowired
    private TokenProfileRepository tokenProfileRepository;

    private final List<TokenProfile> profiles = new ArrayList<>();
    private final List<TokenInstanceReference> tokens = new ArrayList<>();
    private final ExecutorService executor = Executors.newFixedThreadPool(2);
    private Connector connector;
    private ConnectorInterfaceEntity connectorInterface;

    @BeforeEach
    void setUp() {
        Connector value = new Connector();
        value.setName("concurrent-capability-connector-" + UUID.randomUUID());
        value.setUrl("http://localhost:1");
        value.setVersion(ConnectorVersion.V2);
        value.setStatus(ConnectorStatus.CONNECTED);
        connector = connectorRepository.save(value);
        ConnectorInterfaceEntity iface = new ConnectorInterfaceEntity();
        iface.setConnector(connector);
        iface.setConnectorUuid(connector.getUuid());
        iface.setInterfaceCode(ConnectorInterface.CRYPTOGRAPHY);
        iface.setVersion("v2");
        iface.setFeatures(List.of());
        connectorInterface = connectorInterfaceRepository.save(iface);
    }

    @AfterEach
    void tearDown() throws InterruptedException {
        executor.shutdownNow();
        executor.awaitTermination(TIMEOUT_SECONDS, TimeUnit.SECONDS);
        tokenProfileRepository.deleteAll(profiles);
        tokenInstanceReferenceRepository.deleteAll(tokens);
        connectorInterfaceRepository.delete(connectorInterface);
        connectorRepository.delete(connector);
    }

    @Test
    void recordAnswer_waitsForAConcurrentForgetAndThenRefusesItsAnswer() throws Exception {
        // given
        TokenInstanceReference token = persistToken();
        TokenProfile profile = persistProfile(token, null);
        int askedAtRevision = profile.getExportableKeyTypesRevision();
        CountDownLatch forgetHoldsTheLock = new CountDownLatch(1);
        CountDownLatch forgetMayCommit = new CountDownLatch(1);
        Future<?> forget = executor
                .submit(() -> new TransactionTemplate(transactionManager).executeWithoutResult(status -> {
                    keyTransferCapabilityWriter.forgetForToken(token.getUuid());
                    forgetHoldsTheLock.countDown();
                    await(forgetMayCommit);
                }));
        await(forgetHoldsTheLock);

        // when
        Future<Optional<TokenProfileFullModel>> recorded = executor
                .submit(() -> keyTransferCapabilityWriter
                        .recordAnswer(profile.getUuid(), askedAtRevision, RSA_KEY_PAIRS));

        // then
        awaitASessionWaitingOnTheProfileLock();
        forgetMayCommit.countDown();
        forget.get(TIMEOUT_SECONDS, TimeUnit.SECONDS);
        assertTrue(recorded.get(TIMEOUT_SECONDS, TimeUnit.SECONDS).isEmpty());
        TokenProfile stored = tokenProfileRepository.findByUuid(profile.getUuid()).orElseThrow();
        assertNull(stored.getExportableKeyTypes());
        assertEquals(askedAtRevision + 1, stored.getExportableKeyTypesRevision());
    }

    @Test
    void forgetForConnector_dropsTheAnswersOfEveryProfileBehindTheConnector() {
        // given
        TokenProfile first = persistProfile(persistToken(), RSA_KEY_PAIRS);
        TokenProfile second = persistProfile(persistToken(), RSA_KEY_PAIRS);

        // when
        keyTransferCapabilityWriter.forgetForConnector(connector.getUuid());

        // then
        assertNull(tokenProfileRepository.findByUuid(first.getUuid()).orElseThrow().getExportableKeyTypes());
        assertNull(tokenProfileRepository.findByUuid(second.getUuid()).orElseThrow().getExportableKeyTypes());
    }

    private TokenInstanceReference persistToken() {
        TokenInstanceReference value = new TokenInstanceReference();
        value.setName("concurrent-capability-token-" + UUID.randomUUID());
        value.setConnector(connector);
        value.setConnectorInterface(connectorInterface);
        value.setKind("SOFT");
        value.setStatus(TokenInstanceStatus.UNKNOWN);
        TokenInstanceReference saved = tokenInstanceReferenceRepository.save(value);
        tokens.add(saved);
        return saved;
    }

    private TokenProfile persistProfile(TokenInstanceReference token, List<TransferableKeyType> answer) {
        TokenProfile value = new TokenProfile();
        value.setName("concurrent-capability-profile-" + UUID.randomUUID());
        value.setTokenInstanceReference(token);
        value.setEnabled(true);
        value.setExportableKeyTypes(answer);
        TokenProfile saved = tokenProfileRepository.save(value);
        profiles.add(saved);
        return saved;
    }

    /** Waits until the database reports a session blocked on a lock over a token profile row. */
    private void awaitASessionWaitingOnTheProfileLock() {
        Awaitility
                .await("a session waiting for the profile's row lock")
                .atMost(Duration.ofSeconds(TIMEOUT_SECONDS))
                .pollInterval(Duration.ofMillis(20))
                .until(() -> sessionsWaitingOnTheProfileLock() > 0);
    }

    private int sessionsWaitingOnTheProfileLock() {
        Integer waiting = jdbcTemplate
                .queryForObject("SELECT count(*) FROM pg_stat_activity WHERE wait_event_type = 'Lock'"
                        + " AND query ILIKE '%token_profile%' AND datname = current_database()", Integer.class);
        return waiting == null ? 0 : waiting;
    }

    private static void await(CountDownLatch latch) {
        try {
            if (!latch.await(TIMEOUT_SECONDS, TimeUnit.SECONDS)) {
                throw new IllegalStateException("Timed out waiting for the other transaction");
            }
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new IllegalStateException("Interrupted waiting for the other transaction", e);
        }
    }
}
