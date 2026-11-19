package com.otilm.core.integration.dao;

import com.otilm.api.model.core.settings.SettingsSection;
import com.otilm.core.dao.repository.SettingRepository;
import com.otilm.core.service.CryptographicKeyInternalService;
import com.otilm.core.util.BaseSpringBootTest;
import com.zaxxer.hikari.HikariDataSource;
import java.sql.SQLException;
import java.util.Collections;
import java.util.List;
import java.util.UUID;
import java.util.concurrent.Callable;
import java.util.concurrent.CyclicBarrier;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import javax.sql.DataSource;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.TransactionDefinition;
import org.springframework.transaction.support.TransactionTemplate;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;

/**
 * Every thread first takes a pooled connection and then asks for the database again, so with as many threads as the
 * pool has connections, a thread that kept its first connection while waiting for another would wait for good.
 */
class DatabaseConnectionHandlingITest extends BaseSpringBootTest {

    private static final long WAIT_SECONDS = 60L;

    @Autowired
    private PlatformTransactionManager transactionManager;

    @Autowired
    private DataSource dataSource;

    @Autowired
    private SettingRepository settingRepository;

    @Autowired
    private CryptographicKeyInternalService cryptographicKeyService;

    @Test
    void completesEveryTransaction_whenEveryThreadFirstReadOutsideATransaction() throws Exception {
        // given
        int everyConnection = readPoolSize();
        CyclicBarrier allHaveRead = new CyclicBarrier(everyConnection);
        TransactionTemplate outsideATransaction = createTransactionTemplate(
                TransactionDefinition.PROPAGATION_NOT_SUPPORTED);
        TransactionTemplate submission = createTransactionTemplate(TransactionDefinition.PROPAGATION_REQUIRED);
        // A declared query method runs in no transaction of its own, unlike the inherited count()
        Callable<Long> readThenSubmit = () -> outsideATransaction.execute(status -> {
            settingRepository.findBySection(SettingsSection.PLATFORM);
            awaitOthers(allHaveRead);
            return submission.execute(inner -> settingRepository.count());
        });

        // when
        List<Future<Long>> outcomes = runOnEveryConnection(everyConnection, readThenSubmit);

        // then
        assertThat(outcomes).allSatisfy(outcome -> assertThatCode(outcome::get).doesNotThrowAnyException());
    }

    @Test
    void completesEveryKeyLookup_whenEveryThreadHoldsATransaction() throws Exception {
        // given
        int everyConnection = readPoolSize();
        CyclicBarrier allInATransaction = new CyclicBarrier(everyConnection);
        TransactionTemplate submission = createTransactionTemplate(TransactionDefinition.PROPAGATION_REQUIRED);
        Callable<UUID> lookUpTheRequestKey = () -> submission.execute(status -> {
            settingRepository.count();
            awaitOthers(allInATransaction);
            return cryptographicKeyService.findKeyByFingerprint("no-key-has-this-fingerprint");
        });

        // when
        List<Future<UUID>> outcomes = runOnEveryConnection(everyConnection, lookUpTheRequestKey);

        // then
        assertThat(outcomes).allSatisfy(outcome -> assertThatCode(outcome::get).doesNotThrowAnyException());
    }

    // ── Helpers ───────────────────────────────────────────────────────────────

    private int readPoolSize() throws SQLException {
        return dataSource.unwrap(HikariDataSource.class).getMaximumPoolSize();
    }

    private TransactionTemplate createTransactionTemplate(int propagation) {
        TransactionTemplate template = new TransactionTemplate(transactionManager);
        template.setPropagationBehavior(propagation);
        return template;
    }

    private static <T> List<Future<T>> runOnEveryConnection(int threads, Callable<T> task) throws InterruptedException {
        ExecutorService executor = Executors.newFixedThreadPool(threads);
        try {
            return executor.invokeAll(Collections.nCopies(threads, task), WAIT_SECONDS, TimeUnit.SECONDS);
        } finally {
            executor.shutdownNow();
        }
    }

    private static void awaitOthers(CyclicBarrier barrier) {
        try {
            barrier.await(WAIT_SECONDS, TimeUnit.SECONDS);
        } catch (Exception e) {
            throw new IllegalStateException("Not every thread reached the barrier", e);
        }
    }
}
