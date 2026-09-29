package com.otilm.core.integration.service;

import com.otilm.api.exception.NotFoundException;
import com.otilm.api.model.client.connector.v2.ConnectorInterface;
import com.otilm.api.model.client.connector.v2.ConnectorVersion;
import com.otilm.api.model.client.cryptography.key.KeyRequestType;
import com.otilm.api.model.common.enums.cryptography.KeyAlgorithm;
import com.otilm.api.model.connector.cryptography.enums.TokenInstanceStatus;
import com.otilm.api.model.core.connector.ConnectorStatus;
import com.otilm.api.model.core.cryptography.key.KeyUsage;
import com.otilm.core.dao.entity.Connector;
import com.otilm.core.dao.entity.ConnectorInterfaceEntity;
import com.otilm.core.dao.entity.TokenInstanceReference;
import com.otilm.core.dao.entity.TokenProfile;
import com.otilm.core.dao.repository.ConnectorInterfaceRepository;
import com.otilm.core.dao.repository.ConnectorRepository;
import com.otilm.core.dao.repository.TokenInstanceReferenceRepository;
import com.otilm.core.dao.repository.TokenProfileRepository;
import com.otilm.core.model.crypto.KeyTransfer;
import com.otilm.core.model.crypto.TokenProfileFullModel;
import com.otilm.core.model.crypto.TransferableKeyType;
import com.otilm.core.service.writer.KeyTransferCapabilityWriter;
import com.otilm.core.service.writer.TokenProfileWriter;
import com.otilm.core.util.BaseSpringBootTest;
import jakarta.persistence.EntityManager;
import jakarta.persistence.EntityManagerFactory;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;
import org.awaitility.Awaitility;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.orm.jpa.EntityManagerHolder;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.support.TransactionSynchronizationManager;
import org.springframework.transaction.support.TransactionTemplate;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Committed transactions on separate threads, as in production: an answer asked for before a change must never be
 * recorded after it, whichever way the two writes meet on the profile's row lock, and a write must never put back what
 * another request changed after the writing request had loaded the profile.
 */
class KeyTransferCapabilityWriterConcurrencyITest extends BaseSpringBootTest {

    private static final long TIMEOUT_SECONDS = 30;

    private static final List<TransferableKeyType> RSA_KEY_PAIRS = List
            .of(new TransferableKeyType(KeyRequestType.KEY_PAIR, Set.of(KeyAlgorithm.RSA)));

    private static final List<TransferableKeyType> ECDSA_KEY_PAIRS = List
            .of(new TransferableKeyType(KeyRequestType.KEY_PAIR, Set.of(KeyAlgorithm.ECDSA)));

    @Autowired
    private KeyTransferCapabilityWriter keyTransferCapabilityWriter;

    @Autowired
    private TokenProfileWriter tokenProfileWriter;

    @Autowired
    private EntityManagerFactory entityManagerFactory;

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
        int askedAtRevision = profile.getKeyTypesRevision();
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
                        .recordAnswer(profile.getUuid(), askedAtRevision, KeyTransfer.EXPORT, RSA_KEY_PAIRS));

        // then
        awaitASessionWaitingOnTheProfileLock();
        forgetMayCommit.countDown();
        forget.get(TIMEOUT_SECONDS, TimeUnit.SECONDS);
        assertTrue(recorded.get(TIMEOUT_SECONDS, TimeUnit.SECONDS).isEmpty());
        TokenProfile stored = tokenProfileRepository.findByUuid(profile.getUuid()).orElseThrow();
        assertNull(stored.getExportableKeyTypes());
        assertEquals(askedAtRevision + 1, stored.getKeyTypesRevision());
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

    @ParameterizedTest
    @EnumSource(KeyTransfer.class)
    void recordAnswer_recordsOneDirectionAndKeepsTheOther(KeyTransfer direction) throws Exception {
        // given
        TokenProfile profile = persistProfile(persistToken(), null);
        profile.setImportableKeyTypes(ECDSA_KEY_PAIRS);
        profile.setExportableKeyTypes(ECDSA_KEY_PAIRS);
        tokenProfileRepository.saveAndFlush(profile);

        // when
        keyTransferCapabilityWriter
                .recordAnswer(profile.getUuid(), profile.getKeyTypesRevision(), direction, RSA_KEY_PAIRS);

        // then
        TokenProfile stored = tokenProfileRepository.findByUuid(profile.getUuid()).orElseThrow();
        assertEquals(direction == KeyTransfer.IMPORT ? RSA_KEY_PAIRS : ECDSA_KEY_PAIRS, stored.getImportableKeyTypes());
        assertEquals(direction == KeyTransfer.EXPORT ? RSA_KEY_PAIRS : ECDSA_KEY_PAIRS, stored.getExportableKeyTypes());
    }

    @Test
    void forgetForToken_forgetsBothDirectionsAtOnce() {
        // given
        TokenInstanceReference token = persistToken();
        TokenProfile profile = persistProfile(token, RSA_KEY_PAIRS);
        profile.setImportableKeyTypes(RSA_KEY_PAIRS);
        tokenProfileRepository.saveAndFlush(profile);
        int revision = profile.getKeyTypesRevision();

        // when
        keyTransferCapabilityWriter.forgetForToken(token.getUuid());

        // then
        TokenProfile stored = tokenProfileRepository.findByUuid(profile.getUuid()).orElseThrow();
        assertNull(stored.getImportableKeyTypes());
        assertNull(stored.getExportableKeyTypes());
        assertEquals(revision + 1, stored.getKeyTypesRevision());
    }

    @Test
    void recordAnswer_refusesAnAnswerAskedForBeforeAChangeTheRequestHadNotSeen() throws Exception {
        // given
        TokenProfile profile = persistProfile(persistToken(), null);

        // when
        Optional<TokenProfileFullModel> recorded = withARequestBoundEntityManager(profile.getUuid(), held -> {
            int askedAtRevision = held.getKeyTypesRevision();
            behindTheRequest(() -> tokenProfileWriter.setUsages(held.getUuid(), List.of(KeyUsage.SIGN)));
            Optional<TokenProfileFullModel> answer = keyTransferCapabilityWriter
                    .recordAnswer(held.getUuid(), askedAtRevision, KeyTransfer.EXPORT, RSA_KEY_PAIRS);
            assertEquals(List.of(KeyUsage.SIGN), held.getUsage(), "the writer decided on the request's own copy");
            return answer;
        });

        // then
        assertTrue(recorded.isEmpty());
        TokenProfile stored = tokenProfileRepository.findByUuid(profile.getUuid()).orElseThrow();
        assertNull(stored.getExportableKeyTypes());
        assertEquals(List.of(KeyUsage.SIGN), stored.getUsage());
    }

    @Test
    void forgetForToken_countsAChangeTheRequestHadNotSeenAndKeepsIt() throws Exception {
        // given
        TokenInstanceReference token = persistToken();
        TokenProfile profile = persistProfile(token, RSA_KEY_PAIRS);
        int revision = profile.getKeyTypesRevision();

        // when
        withARequestBoundEntityManager(profile.getUuid(), held -> {
            behindTheRequest(() -> tokenProfileWriter.setUsages(held.getUuid(), List.of(KeyUsage.SIGN)));
            keyTransferCapabilityWriter.forgetForToken(token.getUuid());
            assertEquals(revision + 2, held.getKeyTypesRevision(), "the writer decided on the request's own copy");
            return null;
        });

        // then
        TokenProfile stored = tokenProfileRepository.findByUuid(profile.getUuid()).orElseThrow();
        assertEquals(revision + 2, stored.getKeyTypesRevision());
        assertEquals(List.of(KeyUsage.SIGN), stored.getUsage());
    }

    @Test
    void setUsagesScoped_countsAForgetTheRequestHadNotSeenAndKeepsWhatElseChanged() throws Exception {
        // given
        TokenInstanceReference token = persistToken();
        TokenProfile profile = persistProfile(token, RSA_KEY_PAIRS);
        int revision = profile.getKeyTypesRevision();

        // when
        withARequestBoundEntityManager(profile.getUuid(), held -> {
            behindTheRequest(() -> {
                tokenProfileWriter.setEnabled(held.getUuid(), false);
                keyTransferCapabilityWriter.forgetForToken(token.getUuid());
            });
            tokenProfileWriter.setUsagesScoped(token.getUuid(), held.getUuid(), List.of(KeyUsage.SIGN));
            assertEquals(revision + 2, held.getKeyTypesRevision(), "the writer decided on the request's own copy");
            return null;
        });

        // then
        TokenProfile stored = tokenProfileRepository.findByUuid(profile.getUuid()).orElseThrow();
        assertEquals(revision + 2, stored.getKeyTypesRevision());
        assertFalse(stored.getEnabled());
    }

    @Test
    void setEnabled_doesNotRestoreAnAnswerForgottenBehindTheRequest() throws Exception {
        // given
        TokenProfile profile = persistProfile(persistToken(), RSA_KEY_PAIRS);
        int revision = profile.getKeyTypesRevision();

        // when
        withARequestBoundEntityManager(profile.getUuid(), held -> {
            behindTheRequest(() -> tokenProfileWriter.setUsages(held.getUuid(), List.of(KeyUsage.SIGN)));
            tokenProfileWriter.setEnabled(held.getUuid(), false);
            assertNull(held.getExportableKeyTypes(), "the writer decided on the request's own copy");
            return null;
        });

        // then
        TokenProfile stored = tokenProfileRepository.findByUuid(profile.getUuid()).orElseThrow();
        assertNull(stored.getExportableKeyTypes());
        assertEquals(revision + 1, stored.getKeyTypesRevision());
        assertEquals(List.of(KeyUsage.SIGN), stored.getUsage());
        assertFalse(stored.getEnabled());
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

    /**
     * Binds one EntityManager to the thread for the call, as open-in-view does for a request, and hands the call the
     * profile as that EntityManager loaded it. The writers' transactions inside the call use this EntityManager, so
     * their locked reads answer from its persistence context.
     */
    private <T> T withARequestBoundEntityManager(UUID profileUuid, RequestCall<T> call) throws NotFoundException {
        EntityManager bound = entityManagerFactory.createEntityManager();
        TransactionSynchronizationManager.bindResource(entityManagerFactory, new EntityManagerHolder(bound));
        try {
            return call.apply(bound.find(TokenProfile.class, profileUuid));
        } finally {
            TransactionSynchronizationManager.unbindResource(entityManagerFactory);
            bound.close();
        }
    }

    /** Commits the change from another thread, with a persistence context of its own, as another request does. */
    private void behindTheRequest(Change change) {
        try {
            executor.submit(() -> {
                change.apply();
                return null;
            }).get(TIMEOUT_SECONDS, TimeUnit.SECONDS);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new IllegalStateException("Interrupted waiting for the other request", e);
        } catch (ExecutionException | TimeoutException e) {
            throw new IllegalStateException("The other request did not commit its change", e);
        }
    }

    @FunctionalInterface
    private interface RequestCall<T> {
        T apply(TokenProfile held) throws NotFoundException;
    }

    @FunctionalInterface
    private interface Change {
        void apply() throws NotFoundException;
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
