package com.otilm.core.integration.service;

import com.otilm.api.exception.AlreadyExistException;
import com.otilm.api.exception.NotFoundException;
import com.otilm.api.model.core.auth.Resource;
import com.otilm.core.dao.entity.Certificate;
import com.otilm.core.dao.entity.CertificateRequestEntity;
import com.otilm.core.dao.entity.ComplianceProfile;
import com.otilm.core.dao.entity.ComplianceProfileAssociation;
import com.otilm.core.dao.repository.CertificateRepository;
import com.otilm.core.dao.repository.CertificateRequestRepository;
import com.otilm.core.dao.repository.ComplianceProfileAssociationRepository;
import com.otilm.core.dao.repository.ComplianceProfileRepository;
import com.otilm.core.service.writer.CertificateRequestWriter;
import com.otilm.core.service.writer.ComplianceProfileAssociationWriter;
import com.otilm.core.util.BaseSpringBootTest;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.Base64;
import java.util.List;
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

import static com.otilm.core.util.builders.CertificateBuilder.aCertificate;
import static com.otilm.core.util.builders.CertificateRequestEntityBuilder.aCertificateRequest;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * Each worker runs its own transaction on its own thread: the advisory-lock serialization under test only exists
 * between separate transactions, so nothing here may share the test-managed one.
 */
class ComplianceProfileAssociationWriterConcurrencyITest extends BaseSpringBootTest {

    @Autowired
    private ComplianceProfileAssociationWriter complianceProfileAssociationWriter;

    @Autowired
    private CertificateRequestWriter certificateRequestWriter;

    @Autowired
    private ComplianceProfileAssociationRepository complianceProfileAssociationRepository;

    @Autowired
    private ComplianceProfileRepository complianceProfileRepository;

    @Autowired
    private CertificateRepository certificateRepository;

    @Autowired
    private CertificateRequestRepository certificateRequestRepository;

    @Autowired
    private PlatformTransactionManager transactionManager;

    @Autowired
    private JdbcTemplate jdbcTemplate;

    private TransactionTemplate transactionTemplate;
    private ExecutorService executor;

    @BeforeEach
    void setUpConcurrency() {
        transactionTemplate = new TransactionTemplate(transactionManager);
        executor = Executors.newFixedThreadPool(2);
    }

    @AfterEach
    void shutDownExecutor() {
        executor.shutdownNow();
    }

    @Test
    void purgeRunningConcurrentlyWithCreateStillRemovesTheRacingAssociation() throws Exception {
        ComplianceProfile profile = newComplianceProfile();
        Certificate certificate = newCertificate();
        CountDownLatch created = new CountDownLatch(1);
        CountDownLatch mayCommitCreate = new CountDownLatch(1);

        Future<ComplianceProfileAssociation> creator = executor.submit(() -> transactionTemplate.execute(status -> {
            ComplianceProfileAssociation saved = create(profile, Resource.CERTIFICATE, certificate.getUuid());
            created.countDown();
            await(mayCommitCreate);
            return saved;
        }));

        assertThat(created.await(10, TimeUnit.SECONDS)).isTrue();

        Future<Integer> purger = executor.submit(() -> transactionTemplate.execute(status -> {
            int purged = complianceProfileAssociationWriter
                    .deleteAllForObject(Resource.CERTIFICATE, certificate.getUuid());
            certificateRepository.delete(certificate);
            return purged;
        }));

        awaitAdvisoryLockWaiter();
        mayCommitCreate.countDown();

        assertThat(creator.get(10, TimeUnit.SECONDS)).isNotNull();
        assertThat(purger.get(10, TimeUnit.SECONDS)).isEqualTo(1);
        assertThat(hasAssociation(Resource.CERTIFICATE, certificate.getUuid())).isFalse();
    }

    @Test
    void createBlockedByAnInFlightObjectPurgeFailsOnceTheObjectIsGone() throws Exception {
        ComplianceProfile profile = newComplianceProfile();
        Certificate certificate = newCertificate();
        CountDownLatch purged = new CountDownLatch(1);
        CountDownLatch mayCommitPurge = new CountDownLatch(1);

        Future<Integer> purger = executor.submit(() -> transactionTemplate.execute(status -> {
            int removed = complianceProfileAssociationWriter
                    .deleteAllForObject(Resource.CERTIFICATE, certificate.getUuid());
            certificateRepository.delete(certificate);
            certificateRepository.flush();
            purged.countDown();
            await(mayCommitPurge);
            return removed;
        }));

        assertThat(purged.await(10, TimeUnit.SECONDS)).isTrue();

        Future<ComplianceProfileAssociation> creator = executor
                .submit(() -> transactionTemplate
                        .execute(status -> create(profile, Resource.CERTIFICATE, certificate.getUuid())));

        awaitAdvisoryLockWaiter();
        mayCommitPurge.countDown();

        assertThat(purger.get(10, TimeUnit.SECONDS)).isZero();
        assertThatThrownBy(() -> creator.get(10, TimeUnit.SECONDS)).hasRootCauseInstanceOf(NotFoundException.class);
        assertThat(hasAssociation(Resource.CERTIFICATE, certificate.getUuid())).isFalse();
    }

    @Test
    void requestPurgeRunningConcurrentlyWithCreateStillRemovesTheRacingAssociation() throws Exception {
        ComplianceProfile profile = newComplianceProfile();
        CertificateRequestEntity request = newCertificateRequest();
        Certificate certificate = newCertificateOf(request);
        CountDownLatch created = new CountDownLatch(1);
        CountDownLatch mayCommitCreate = new CountDownLatch(1);

        Future<ComplianceProfileAssociation> creator = executor.submit(() -> transactionTemplate.execute(status -> {
            ComplianceProfileAssociation saved = create(profile, Resource.CERTIFICATE_REQUEST, request.getUuid());
            created.countDown();
            await(mayCommitCreate);
            return saved;
        }));

        assertThat(created.await(10, TimeUnit.SECONDS)).isTrue();

        Future<Integer> purger = executor.submit(() -> transactionTemplate.execute(status -> {
            certificateRepository.delete(certificate);
            return certificateRequestWriter.deleteUnreferenced(List.of(request.getUuid()));
        }));

        awaitAdvisoryLockWaiter();
        mayCommitCreate.countDown();

        assertThat(creator.get(10, TimeUnit.SECONDS)).isNotNull();
        assertThat(purger.get(10, TimeUnit.SECONDS)).isEqualTo(1);
        assertThat(hasAssociation(Resource.CERTIFICATE_REQUEST, request.getUuid())).isFalse();
        assertThat(certificateRequestRepository.existsById(request.getUuid())).isFalse();
    }

    private ComplianceProfile newComplianceProfile() {
        ComplianceProfile profile = new ComplianceProfile();
        profile.setName("tst-compliance-profile-" + UUID.randomUUID());
        return complianceProfileRepository.saveAndFlush(profile);
    }

    private Certificate newCertificate() {
        return certificateRepository
                .saveAndFlush(aCertificate()
                        .withSerialNumber(UUID.randomUUID().toString())
                        .withFingerprint(UUID.randomUUID().toString())
                        .build());
    }

    private Certificate newCertificateOf(CertificateRequestEntity request) {
        return certificateRepository
                .saveAndFlush(aCertificate()
                        .withSerialNumber(UUID.randomUUID().toString())
                        .withFingerprint(UUID.randomUUID().toString())
                        .withCertificateRequest(request)
                        .withCertificateRequestUuid(request.getUuid())
                        .build());
    }

    private CertificateRequestEntity newCertificateRequest() {
        String content = Base64
                .getEncoder()
                .encodeToString(UUID.randomUUID().toString().getBytes(StandardCharsets.UTF_8));
        return certificateRequestRepository.saveAndFlush(aCertificateRequest().withContent(content).build());
    }

    private ComplianceProfileAssociation create(ComplianceProfile profile, Resource resource, UUID objectUuid) {
        try {
            return complianceProfileAssociationWriter.create(profile.getUuid(), resource, objectUuid);
        } catch (NotFoundException | AlreadyExistException e) {
            throw new IllegalStateException(e);
        }
    }

    private boolean hasAssociation(Resource resource, UUID objectUuid) {
        return complianceProfileAssociationRepository.existsByResourceAndObjectUuidIn(resource, List.of(objectUuid));
    }

    /**
     * The interleaving under test only exists while the second worker sits in a lock wait, so the first worker must not
     * commit before that wait is observable in pg_locks; timing out here means the lock was never contended, so the
     * serialization itself is broken, not the test.
     */
    private void awaitAdvisoryLockWaiter() {
        Awaitility
                .await()
                .atMost(Duration.ofSeconds(10))
                .until(() -> jdbcTemplate
                        .queryForObject("SELECT count(*) FROM pg_locks WHERE locktype = 'advisory' AND NOT granted",
                                Long.class) >= 1);
    }

    private static void await(CountDownLatch latch) {
        try {
            if (!latch.await(10, TimeUnit.SECONDS)) {
                throw new IllegalStateException("Latch was not released in time");
            }
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new IllegalStateException(e);
        }
    }
}
