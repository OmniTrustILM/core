package com.otilm.core.integration.repository;

import com.otilm.core.dao.entity.Certificate;
import com.otilm.core.dao.entity.CryptographicKey;
import com.otilm.core.dao.repository.CertificateRepository;
import com.otilm.core.dao.repository.CryptographicKeyRepository;
import com.otilm.core.util.BaseSpringBootTest;
import java.sql.SQLException;
import java.util.UUID;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.TimeUnit;
import javax.sql.DataSource;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.core.NestedExceptionUtils;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.support.TransactionTemplate;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertThrows;

/** Proves each pessimistic lock query on an entity with an inverse {@code @OneToOne} really takes the row lock. */
class PessimisticLockITest extends BaseSpringBootTest {

    /** PostgreSQL's SQLSTATE for a NOWAIT lock request on a row another transaction holds. */
    private static final String LOCK_NOT_AVAILABLE = "55P03";

    @Autowired
    private CertificateRepository certificateRepository;

    @Autowired
    private CryptographicKeyRepository cryptographicKeyRepository;

    @Autowired
    private PlatformTransactionManager transactionManager;

    @Autowired
    private DataSource dataSource;

    @Test
    void certificateLockQueryTakesTheRowLock() {
        UUID uuid = certificateRepository.save(new Certificate()).getUuid();
        assertRowLockedWhile("certificate", uuid,
                () -> certificateRepository.findAndLockWithAssociationsByUuid(uuid).orElseThrow());
    }

    @Test
    void cryptographicKeyLockQueryTakesTheRowLock() {
        UUID uuid = cryptographicKeyRepository.save(new CryptographicKey()).getUuid();
        assertRowLockedWhile("cryptographic_key", uuid,
                () -> cryptographicKeyRepository.findForUpdateByUuid(uuid).orElseThrow());
    }

    private void assertRowLockedWhile(String table, UUID uuid, Runnable lockingQuery) {
        JdbcTemplate otherConnection = new JdbcTemplate(dataSource);
        new TransactionTemplate(transactionManager).executeWithoutResult(status -> {
            lockingQuery.run();
            CompletableFuture<?> probe = CompletableFuture
                    .runAsync(() -> otherConnection
                            .queryForList(
                                    "SELECT uuid FROM " + dbSchema + "." + table + " WHERE uuid = ? FOR UPDATE NOWAIT",
                                    uuid));
            ExecutionException e = assertThrows(ExecutionException.class, () -> probe.get(10, TimeUnit.SECONDS),
                    "the row was not locked");
            Throwable cause = NestedExceptionUtils.getMostSpecificCause(e.getCause());
            assertEquals(LOCK_NOT_AVAILABLE, assertInstanceOf(SQLException.class, cause).getSQLState(),
                    cause.getMessage());
        });
    }
}
