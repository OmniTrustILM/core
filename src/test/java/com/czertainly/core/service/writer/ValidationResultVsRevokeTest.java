package com.czertainly.core.service.writer;

import com.otilm.api.model.core.certificate.CertificateState;
import com.otilm.api.model.core.certificate.CertificateValidationStatus;
import com.czertainly.core.dao.entity.Certificate;
import com.czertainly.core.dao.repository.CertificateRepository;
import com.czertainly.core.util.BaseSpringBootTest;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.support.TransactionTemplate;

import java.time.OffsetDateTime;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.assertEquals;

/**
 * <p>Verifies that {@link CertificateValidationWriter}'s targeted UPDATE does not clobber columns
 * the validation path does not own — most importantly {@code state}.
 *
 * <p>This test simulates the race by ordering the steps deterministically: persist {@code ISSUED}, directly UPDATE {@code state}
 * to {@code PENDING_REVOKE} via JDBC (modeling the concurrent revoke commit), then call the writer with a stale in-memory view.
 * Under the targeted UPDATE the writer issues, only targeted columns change — {@code state} survives.
 */
class ValidationResultVsRevokeTest extends BaseSpringBootTest {

    @Autowired
    private CertificateValidationWriter validationWriter;

    @Autowired
    private CertificateRepository certificateRepository;

    @Autowired
    private JdbcTemplate jdbcTemplate;

    @Autowired
    private PlatformTransactionManager transactionManager;

    @Test
    void applyValidationResultDoesNotClobberConcurrentlyUpdatedState() {
        Certificate cert = new Certificate();
        cert.setCommonName("validationVsRevokeTest");
        cert.setSerialNumber(UUID.randomUUID().toString());
        cert.setFingerprint(UUID.randomUUID().toString());
        cert.setState(CertificateState.ISSUED);
        cert.setValidationStatus(CertificateValidationStatus.NOT_CHECKED);
        cert = certificateRepository.save(cert);
        UUID uuid = cert.getUuid();

        // Concurrent revoke commits before the validate path's writer call.
        int updated = jdbcTemplate.update(
                "UPDATE core.certificate SET state = ?, i_upd = CURRENT_TIMESTAMP WHERE uuid = ?",
                CertificateState.PENDING_REVOKE.name(), uuid);
        assertEquals(1, updated, "JDBC UPDATE must affect exactly one row");

        // Validate path now writes its result through the writer. Targeted UPDATE — must not touch state.
        validationWriter.applyValidationResult(uuid, CertificateValidationStatus.FAILED, OffsetDateTime.now(), "{\"failed\":true}");

        String finalState = jdbcTemplate.queryForObject(
                "SELECT state FROM core.certificate WHERE uuid = ?", String.class, uuid);
        assertEquals(CertificateState.PENDING_REVOKE.name(), finalState,
                "writer.applyValidationResult must not modify state.");

        Certificate reloaded = certificateRepository.findByUuid(uuid).orElseThrow();
        assertEquals(CertificateValidationStatus.FAILED, reloaded.getValidationStatus(),
                "writer must have applied the validation status it was asked to write");
    }

    /**
     * Verifies that {@code @Modifying(clearAutomatically = true)} on {@code updateValidationResult} prevents
     * a stale managed entity from being flushed back after the bulk UPDATE.
     */
    @Test
    void applyValidationResultWithAmbientTxDoesNotReflushStaleState() {
        Certificate cert = new Certificate();
        cert.setCommonName("entityDirtyingTest");
        cert.setSerialNumber(UUID.randomUUID().toString());
        cert.setFingerprint(UUID.randomUUID().toString());
        cert.setState(CertificateState.ISSUED);
        cert.setValidationStatus(CertificateValidationStatus.NOT_CHECKED);
        cert = certificateRepository.save(cert);
        UUID uuid = cert.getUuid();

        new TransactionTemplate(transactionManager).execute(status -> {
            // Load into L1 cache so Hibernate tracks this entity
            Certificate managed = certificateRepository.findByUuid(uuid).orElseThrow();
            assertEquals(CertificateState.ISSUED, managed.getState());

            // Concurrent actor changes state via JDBC (bypasses JPA, same tx so visible immediately)
            jdbcTemplate.update(
                    "UPDATE core.certificate SET state = ?, i_upd = CURRENT_TIMESTAMP WHERE uuid = ?",
                    CertificateState.PENDING_REVOKE.name(), uuid);

            // Writer joins ambient tx, does bulk UPDATE on validation columns and clears the persistence context.
            validationWriter.applyValidationResult(uuid, CertificateValidationStatus.FAILED, OffsetDateTime.now(), null);

            // Simulate X509CertificateValidator post-writer in-memory sync
            managed.setValidationStatus(CertificateValidationStatus.FAILED);
            managed.setStatusValidationTimestamp(OffsetDateTime.now());
            return null;
        });

        String finalState = jdbcTemplate.queryForObject(
                "SELECT state FROM core.certificate WHERE uuid = ?", String.class, uuid);
        assertEquals(CertificateState.PENDING_REVOKE.name(), finalState,
                "clearAutomatically must evict the stale entity so its state is never re-flushed");
    }
}
