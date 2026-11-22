package com.otilm.core.integration.repository;

import com.otilm.api.model.core.certificate.CertificateState;
import com.otilm.core.dao.entity.Certificate;
import com.otilm.core.dao.repository.CertificateRepository;
import com.otilm.core.util.BaseSpringBootTest;
import jakarta.persistence.EntityManager;
import jakarta.persistence.EntityManagerFactory;
import java.util.Optional;
import java.util.UUID;
import javax.sql.DataSource;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.orm.jpa.EntityManagerHolder;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.support.TransactionSynchronizationManager;
import org.springframework.transaction.support.TransactionTemplate;

import static com.otilm.core.util.builders.CertificateBuilder.aCertificate;
import static org.assertj.core.api.Assertions.assertThat;

class CustomCertificateRepositoryITest extends BaseSpringBootTest {

    @Autowired
    private CertificateRepository certificateRepository;

    @Autowired
    private EntityManagerFactory entityManagerFactory;

    @Autowired
    private PlatformTransactionManager transactionManager;

    @Autowired
    private DataSource dataSource;

    @Test
    void returnsTheStateTheDatabaseHolds_whenTheRequestHoldsAnOlderCopy() {
        // given — the request's EntityManager, which the next transaction runs on, read the certificate before another
        // transaction claimed it
        UUID uuid = certificateRepository.save(aCertificate().withState(CertificateState.REQUESTED).build()).getUuid();
        EntityManager requestEntityManager = entityManagerFactory.createEntityManager();
        TransactionSynchronizationManager
                .bindResource(entityManagerFactory, new EntityManagerHolder(requestEntityManager));
        CertificateState lockedState;
        try {
            requestEntityManager.find(Certificate.class, uuid);
            claimInAnotherTransaction(uuid);

            // when
            lockedState = new TransactionTemplate(transactionManager)
                    .execute(status -> certificateRepository.findAndLockFreshByUuid(uuid).orElseThrow().getState());
        } finally {
            TransactionSynchronizationManager.unbindResource(entityManagerFactory);
            requestEntityManager.close();
        }

        // then
        assertThat(lockedState).isEqualTo(CertificateState.PENDING_ISSUE);
    }

    @Test
    void returnsEmpty_whenNoCertificateHasTheUuid() {
        // given
        var unknownUuid = UUID.randomUUID();

        // when
        Optional<Certificate> locked = new TransactionTemplate(transactionManager)
                .execute(status -> certificateRepository.findAndLockFreshByUuid(unknownUuid));

        // then
        assertThat(locked).isEmpty();
    }

    // ── Helpers ───────────────────────────────────────────────────────────────

    private void claimInAnotherTransaction(UUID uuid) {
        new JdbcTemplate(dataSource)
                .update("UPDATE " + dbSchema + ".certificate SET state = ? WHERE uuid = ?",
                        CertificateState.PENDING_ISSUE.name(), uuid);
    }
}
