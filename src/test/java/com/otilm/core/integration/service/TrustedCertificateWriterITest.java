package com.otilm.core.integration.service;

import com.otilm.api.model.client.trustedcertificate.TrustedCertificatePlatformState;
import com.otilm.api.model.core.certificate.CertificateValidationStatus;
import com.otilm.api.model.core.settings.CertificateSettingsDto;
import com.otilm.api.model.core.settings.CertificateValidationSettingsDto;
import com.otilm.api.model.core.settings.PlatformSettingsDto;
import com.otilm.api.model.core.settings.SettingsSection;
import com.otilm.core.dao.entity.CertificateContent;
import com.otilm.core.dao.entity.TrustedCertificate;
import com.otilm.core.dao.entity.TrustedCertificateSync;
import com.otilm.core.dao.entity.X509CertificateEntity;
import com.otilm.core.dao.repository.CertificateContentRepository;
import com.otilm.core.dao.repository.CertificateRepository;
import com.otilm.core.dao.repository.TrustedCertificateRepository;
import com.otilm.core.dao.repository.TrustedCertificateSyncRepository;
import com.otilm.core.dao.repository.X509CertificateRepository;
import com.otilm.core.messaging.jms.producers.ValidationProducer;
import com.otilm.core.service.writer.TrustedCertificateWriter;
import com.otilm.core.settings.SettingsCache;
import com.otilm.core.util.BaseSpringBootTest;
import com.otilm.core.util.mockbeans.ProducerMocks;
import java.time.OffsetDateTime;
import java.time.ZoneOffset;
import java.time.temporal.ChronoUnit;
import java.util.UUID;
import org.assertj.core.api.ThrowableAssert.ThrowingCallable;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.filter.annotation.TypeExcludeFilters;
import org.springframework.context.annotation.Import;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.TransactionDefinition;
import org.springframework.transaction.support.TransactionTemplate;

import static com.otilm.core.util.builders.CertificateBuilder.aCertificate;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.argThat;
import static org.mockito.Mockito.clearInvocations;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;

@Import(ProducerMocks.class)
@TypeExcludeFilters(ProducerMocks.MockedProducersTypeExcludeFilter.class)
class TrustedCertificateWriterITest extends BaseSpringBootTest {

    @Autowired
    private TrustedCertificateWriter writer;
    @Autowired
    private TrustedCertificateRepository trustedCertificateRepository;
    @Autowired
    private TrustedCertificateSyncRepository trustedCertificateSyncRepository;
    @Autowired
    private X509CertificateRepository x509CertificateRepository;
    @Autowired
    private CertificateRepository certificateRepository;
    @Autowired
    private CertificateContentRepository certificateContentRepository;
    @Autowired
    private ValidationProducer validationProducer;
    @Autowired
    private SettingsCache settingsCache;
    @Autowired
    private PlatformTransactionManager transactionManager;

    @BeforeEach
    void enablePlatformValidation() {
        CertificateValidationSettingsDto validation = new CertificateValidationSettingsDto();
        validation.setEnabled(true);
        CertificateSettingsDto certificates = new CertificateSettingsDto();
        certificates.setValidation(validation);
        PlatformSettingsDto platform = new PlatformSettingsDto();
        platform.setCertificates(certificates);
        settingsCache.cacheSettings(SettingsSection.PLATFORM, platform);
    }

    @Test
    void flagsTheCertificateAndQueuesRevalidation_whenInsertingWithValidation() {
        // given
        X509CertificateEntity untrustedCa = persistCa(false);

        // when
        writer.insert(untrustedCa, true, false, null);

        // then
        assertThat(x509CertificateRepository.findByUuid(untrustedCa.getUuid()).orElseThrow().getTrustedCa()).isTrue();
        verify(validationProducer)
                .produceMessage(argThat(message -> message.getUuids().contains(untrustedCa.getUuid())));
    }

    @Test
    void dropsValidationAtOnce_whenMarkingRemovalPending() {
        // given
        X509CertificateEntity ca = persistCa(false);
        TrustedCertificate row = writer.insert(ca, true, true, TrustedCertificatePlatformState.APPLIED);
        clearInvocations(validationProducer);

        // when
        writer.markRemovalPending(row.getUuid());

        // then
        TrustedCertificate reloaded = trustedCertificateRepository.findById(row.getUuid()).orElseThrow();
        assertThat(reloaded.isValidation()).isFalse();
        assertThat(reloaded.isPlatform()).isFalse();
        assertThat(reloaded.isPlatformRemovalPending()).isTrue();
        assertThat(x509CertificateRepository.findByUuid(ca.getUuid()).orElseThrow().getTrustedCa()).isFalse();
        verify(validationProducer).produceMessage(argThat(message -> message.getUuids().contains(ca.getUuid())));
    }

    @Test
    void keepsValidationTrust_whenInsertingForThePlatformOnly() {
        // given
        X509CertificateEntity caTrustedWithoutRow = persistCa(true);

        // when
        writer.insert(caTrustedWithoutRow, false, true, TrustedCertificatePlatformState.APPLIED);

        // then
        assertThat(x509CertificateRepository.findByUuid(caTrustedWithoutRow.getUuid()).orElseThrow().getTrustedCa())
                .isTrue();
        verify(validationProducer, never()).produceMessage(any());
    }

    @Test
    void leavesTheFlagAlone_whenTheCertificateIsNotACa() {
        // given
        X509CertificateEntity endEntity = certificateRepository
                .saveAndFlush(aCertificate().withFingerprint(UUID.randomUUID().toString()).build());

        // when
        writer.insert(endEntity, true, false, null);

        // then
        assertThat(x509CertificateRepository.findByUuid(endEntity.getUuid()).orElseThrow().getTrustedCa()).isNull();
        verify(validationProducer, never()).produceMessage(any());
    }

    @Test
    void clearsThePendingRemoval_whenThePlatformPurposeIsAddedBack() {
        // given
        X509CertificateEntity ca = persistCa(false);
        TrustedCertificate row = writer.insert(ca, true, true, TrustedCertificatePlatformState.APPLIED);
        writer.markRemovalPending(row.getUuid());

        // when
        writer.setPurposes(row.getUuid(), false, true);

        // then
        TrustedCertificate reloaded = trustedCertificateRepository.findById(row.getUuid()).orElseThrow();
        assertThat(reloaded.isPlatform()).isTrue();
        assertThat(reloaded.isPlatformRemovalPending()).isFalse();
    }

    @Test
    void marksTheRemovalPendingAndKeepsValidation_whenThePlatformPurposeIsDropped() {
        // given
        X509CertificateEntity ca = persistCa(false);
        TrustedCertificate row = writer.insert(ca, true, true, TrustedCertificatePlatformState.APPLIED);
        clearInvocations(validationProducer);

        // when
        writer.setPurposes(row.getUuid(), true, false);

        // then
        TrustedCertificate reloaded = trustedCertificateRepository.findById(row.getUuid()).orElseThrow();
        assertThat(reloaded.isValidation()).isTrue();
        assertThat(reloaded.isPlatform()).isFalse();
        assertThat(reloaded.isPlatformRemovalPending()).isTrue();
        verify(validationProducer, never()).produceMessage(any());
    }

    @Test
    void clearsTheFlagAndQueuesRevalidation_whenTheValidationPurposeIsDropped() {
        // given
        X509CertificateEntity ca = persistCa(false);
        TrustedCertificate row = writer.insert(ca, true, true, TrustedCertificatePlatformState.APPLIED);
        clearInvocations(validationProducer);

        // when
        writer.setPurposes(row.getUuid(), false, true);

        // then
        assertThat(x509CertificateRepository.findByUuid(ca.getUuid()).orElseThrow().getTrustedCa()).isFalse();
        verify(validationProducer).produceMessage(argThat(message -> message.getUuids().contains(ca.getUuid())));
    }

    @Test
    void refusesToDropTheLastPurpose_whenNoRemovalIsPending() {
        // given
        X509CertificateEntity ca = persistCa(false);
        TrustedCertificate validationOnly = writer.insert(ca, true, false, null);

        // when
        ThrowingCallable dropEverything = () -> writer.setPurposes(validationOnly.getUuid(), false, false);

        // then
        assertThatThrownBy(dropEverything).isInstanceOf(IllegalArgumentException.class);
        assertThat(trustedCertificateRepository.findById(validationOnly.getUuid()).orElseThrow().isValidation())
                .isTrue();
    }

    @Test
    void clearsTheFlagAndQueuesRevalidation_whenDeletingAValidationRow() {
        // given
        X509CertificateEntity ca = persistCa(false);
        TrustedCertificate row = writer.insert(ca, true, false, null);
        clearInvocations(validationProducer);

        // when
        writer.delete(row.getUuid());

        // then
        assertThat(trustedCertificateRepository.findById(row.getUuid())).isEmpty();
        assertThat(x509CertificateRepository.findByUuid(ca.getUuid()).orElseThrow().getTrustedCa()).isFalse();
        verify(validationProducer).produceMessage(argThat(message -> message.getUuids().contains(ca.getUuid())));
    }

    @Test
    void storesThePlatformIdentityAndObservation_whenRecorded() {
        // given
        TrustedCertificate row = writer.insert(persistCa(false), false, true, TrustedCertificatePlatformState.PENDING);
        var checkedAt = OffsetDateTime.now(ZoneOffset.UTC).truncatedTo(ChronoUnit.SECONDS);

        // when
        writer.recordPlatformUuid(row.getUuid(), "p1");
        writer.recordObserved(row.getUuid(), TrustedCertificatePlatformState.FAILED, "Deployment failed", checkedAt);

        // then
        TrustedCertificate reloaded = trustedCertificateRepository.findById(row.getUuid()).orElseThrow();
        assertThat(reloaded.getPlatformUuid()).isEqualTo("p1");
        assertThat(reloaded.getPlatformState()).isEqualTo(TrustedCertificatePlatformState.FAILED);
        assertThat(reloaded.getPlatformStateMessage()).isEqualTo("Deployment failed");
        assertThat(reloaded.getPlatformStateCheckedAt().toInstant()).isEqualTo(checkedAt.toInstant());
    }

    @Test
    void keepsAConcurrentObservation_whenTheRowIsSavedFromAnEarlierRead() {
        // given
        TrustedCertificate row = writer.insert(persistCa(false), false, true, TrustedCertificatePlatformState.PENDING);
        var outer = new TransactionTemplate(transactionManager);
        var concurrent = new TransactionTemplate(transactionManager);
        concurrent.setPropagationBehavior(TransactionDefinition.PROPAGATION_REQUIRES_NEW);

        // when
        outer.executeWithoutResult(status -> {
            TrustedCertificate readBefore = trustedCertificateRepository.findById(row.getUuid()).orElseThrow();
            concurrent
                    .executeWithoutResult(inner -> writer
                            .recordObserved(row.getUuid(), TrustedCertificatePlatformState.APPLIED, null,
                                    OffsetDateTime.now()));
            readBefore.setPlatformUuid("p1");
            trustedCertificateRepository.saveAndFlush(readBefore);
        });

        // then
        TrustedCertificate reloaded = trustedCertificateRepository.findById(row.getUuid()).orElseThrow();
        assertThat(reloaded.getPlatformState()).isEqualTo(TrustedCertificatePlatformState.APPLIED);
        assertThat(reloaded.getPlatformUuid()).isEqualTo("p1");
    }

    @Test
    void createsTheSyncRecord_whenTheSchemaHasNone() {
        // given — the test schema is built from the entities, without the row the migration inserts
        var checkedAt = OffsetDateTime.now(ZoneOffset.UTC).truncatedTo(ChronoUnit.SECONDS);

        // when
        writer.recordSync(true, checkedAt, null);

        // then
        TrustedCertificateSync sync = trustedCertificateSyncRepository
                .findById(TrustedCertificateSync.SINGLETON_UUID)
                .orElseThrow();
        assertThat(sync.isInitialImportDone()).isTrue();
        assertThat(sync.getLastSuccessfulCheckAt().toInstant()).isEqualTo(checkedAt.toInstant());
        assertThat(sync.getLastError()).isNull();
    }

    // ── Helpers ───────────────────────────────────────────────────────────────

    private X509CertificateEntity persistCa(boolean trustedCa) {
        CertificateContent content = new CertificateContent();
        content.setFingerprint(UUID.randomUUID().toString());
        content.setContent("ca-content");
        content = certificateContentRepository.saveAndFlush(content);
        X509CertificateEntity ca = aCertificate()
                .withFingerprint(UUID.randomUUID().toString())
                .withValidationStatus(CertificateValidationStatus.VALID)
                .withTrustedCa(trustedCa)
                .build();
        ca.setCertificateContentId(content.getId());
        return certificateRepository.saveAndFlush(ca);
    }
}
