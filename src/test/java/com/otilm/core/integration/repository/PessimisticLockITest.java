package com.otilm.core.integration.repository;

import com.otilm.core.dao.entity.CryptographicKey;
import com.otilm.core.dao.entity.RaProfile;
import com.otilm.core.dao.repository.CertificateRepository;
import com.otilm.core.dao.repository.CryptographicKeyRepository;
import com.otilm.core.dao.repository.RaProfileRepository;
import com.otilm.core.dao.repository.X509CertificateRepository;
import com.otilm.core.util.BaseSpringBootTest;
import java.sql.SQLException;
import java.util.Set;
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

import static com.otilm.core.util.builders.CertificateBuilder.aCertificate;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertThrows;

/** Proves each pessimistic lock query on an entity with an inverse {@code @OneToOne} really takes the row lock. */
public class PessimisticLockITest extends BaseSpringBootTest {

    /**
     * The lock queries the cases below exercise; LockedInverseOneToOneGuardTest keeps it complete. The query declared
     * on the shared certificate repository is exercised through each repository that inherits it.
     */
    public static final Set<String> LOCK_QUERIES = Set
            .of("CertificateRepository#findAndLockWithAssociationsByUuid",
                    "CertificateBaseRepository#findAndLockWithAssociationsByUuid",
                    "X509CertificateRepository#findAndLockWithAssociationsByUuid",
                    "CryptographicKeyRepository#findForUpdateByUuid", "RaProfileRepository#findWithLockByUuid");

    /** PostgreSQL's SQLSTATE for a NOWAIT lock request on a row another transaction holds. */
    private static final String LOCK_NOT_AVAILABLE = "55P03";

    @Autowired
    private CertificateRepository certificateRepository;

    @Autowired
    private X509CertificateRepository x509CertificateRepository;

    @Autowired
    private CryptographicKeyRepository cryptographicKeyRepository;

    @Autowired
    private RaProfileRepository raProfileRepository;

    @Autowired
    private PlatformTransactionManager transactionManager;

    @Autowired
    private DataSource dataSource;

    @Test
    void locksTheCertificateRow_whenFindingItForUpdate() {
        // given
        UUID uuid = certificateRepository.save(aCertificate().build()).getUuid();

        // when
        Runnable findForUpdate = () -> certificateRepository.findAndLockWithAssociationsByUuid(uuid).orElseThrow();

        // then
        assertRowLockedWhile("certificate", uuid, findForUpdate);
    }

    @Test
    void locksTheCertificateRow_whenFindingItForUpdateThroughTheX509Repository() {
        // given
        UUID uuid = x509CertificateRepository.save(aCertificate().build()).getUuid();

        // when
        Runnable findForUpdate = () -> x509CertificateRepository.findAndLockWithAssociationsByUuid(uuid).orElseThrow();

        // then
        assertRowLockedWhile("certificate", uuid, findForUpdate);
    }

    @Test
    void cryptographicKeyLockQueryTakesTheRowLock() {
        UUID uuid = cryptographicKeyRepository.save(new CryptographicKey()).getUuid();
        assertRowLockedWhile("cryptographic_key", uuid,
                () -> cryptographicKeyRepository.findForUpdateByUuid(uuid).orElseThrow());
    }

    @Test
    void raProfileLockQueryTakesTheRowLock() {
        UUID uuid = raProfileRepository.save(new RaProfile()).getUuid();
        assertRowLockedWhile("ra_profile", uuid, () -> raProfileRepository.findWithLockByUuid(uuid).orElseThrow());
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
