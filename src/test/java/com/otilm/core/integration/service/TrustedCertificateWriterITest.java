package com.otilm.core.integration.service;

import com.otilm.api.model.client.trustedcertificate.TrustedCertificatePlatformState;
import com.otilm.api.model.core.certificate.CertificateValidationStatus;
import com.otilm.api.model.core.settings.CertificateSettingsDto;
import com.otilm.api.model.core.settings.CertificateValidationSettingsDto;
import com.otilm.api.model.core.settings.PlatformSettingsDto;
import com.otilm.api.model.core.settings.SettingsSection;
import com.otilm.core.dao.entity.CertificateContent;
import com.otilm.core.dao.entity.TrustedCertificate;
import com.otilm.core.dao.entity.X509CertificateEntity;
import com.otilm.core.dao.repository.CertificateContentRepository;
import com.otilm.core.dao.repository.CertificateRepository;
import com.otilm.core.dao.repository.TrustedCertificateRepository;
import com.otilm.core.dao.repository.X509CertificateRepository;
import com.otilm.core.messaging.jms.producers.ValidationProducer;
import com.otilm.core.service.writer.TrustedCertificateWriter;
import com.otilm.core.settings.SettingsCache;
import com.otilm.core.util.BaseSpringBootTest;
import com.otilm.core.util.mockbeans.ProducerMocks;
import java.util.UUID;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.filter.annotation.TypeExcludeFilters;
import org.springframework.context.annotation.Import;

import static com.otilm.core.util.builders.CertificateBuilder.aCertificate;
import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.argThat;
import static org.mockito.Mockito.verify;

@Import(ProducerMocks.class)
@TypeExcludeFilters(ProducerMocks.MockedProducersTypeExcludeFilter.class)
class TrustedCertificateWriterITest extends BaseSpringBootTest {

    @Autowired
    private TrustedCertificateWriter writer;
    @Autowired
    private TrustedCertificateRepository trustedCertificateRepository;
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
        X509CertificateEntity untrustedCa = persistUntrustedCa();

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
        X509CertificateEntity ca = persistUntrustedCa();
        TrustedCertificate row = writer.insert(ca, true, true, TrustedCertificatePlatformState.APPLIED);

        // when
        writer.markRemovalPending(row.getUuid());

        // then
        TrustedCertificate reloaded = trustedCertificateRepository.findById(row.getUuid()).orElseThrow();
        assertThat(reloaded.isValidation()).isFalse();
        assertThat(reloaded.isPlatform()).isFalse();
        assertThat(reloaded.isPlatformRemovalPending()).isTrue();
        assertThat(x509CertificateRepository.findByUuid(ca.getUuid()).orElseThrow().getTrustedCa()).isFalse();
    }

    // ── Helpers ───────────────────────────────────────────────────────────────

    private X509CertificateEntity persistUntrustedCa() {
        CertificateContent content = new CertificateContent();
        content.setFingerprint(UUID.randomUUID().toString());
        content.setContent("ca-content");
        content = certificateContentRepository.saveAndFlush(content);
        X509CertificateEntity ca = aCertificate()
                .withFingerprint(UUID.randomUUID().toString())
                .withValidationStatus(CertificateValidationStatus.VALID)
                .withTrustedCa(false)
                .build();
        ca.setCertificateContentId(content.getId());
        return certificateRepository.saveAndFlush(ca);
    }
}
