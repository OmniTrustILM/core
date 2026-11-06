package com.otilm.core.integration.service.impl;

import com.otilm.api.exception.AttributeException;
import com.otilm.api.exception.CertificateOperationException;
import com.otilm.api.exception.NotFoundException;
import com.otilm.api.exception.ValidationException;
import com.otilm.api.model.client.certificate.CertificateUpdateObjectsDto;
import com.otilm.api.model.core.certificate.CertificateValidationStatus;
import com.otilm.api.model.core.settings.CertificateSettingsDto;
import com.otilm.api.model.core.settings.CertificateValidationSettingsDto;
import com.otilm.api.model.core.settings.PlatformSettingsDto;
import com.otilm.api.model.core.settings.SettingsSection;
import com.otilm.core.dao.entity.Certificate;
import com.otilm.core.dao.entity.CertificateContent;
import com.otilm.core.dao.entity.RaProfile;
import com.otilm.core.dao.entity.X509CertificateEntity;
import com.otilm.core.dao.repository.CertificateContentRepository;
import com.otilm.core.dao.repository.CertificateRepository;
import com.otilm.core.dao.repository.RaProfileRepository;
import com.otilm.core.events.transaction.CertificateValidationEvent;
import com.otilm.core.security.authz.SecuredUUID;
import com.otilm.core.service.CertificateExternalService;
import com.otilm.core.settings.SettingsCache;
import com.otilm.core.util.BaseSpringBootTest;
import java.util.List;
import java.util.UUID;
import java.util.concurrent.CopyOnWriteArrayList;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.context.annotation.Bean;
import org.springframework.context.event.EventListener;

import static com.otilm.core.util.builders.CertificateBuilder.aCertificate;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class UpdateTrustedCaMarkITest extends BaseSpringBootTest {

    @TestConfiguration
    static class EventCaptorConfig {
        @Bean
        EventCaptor eventCaptor() {
            return new EventCaptor();
        }
    }

    static class EventCaptor {
        private final List<CertificateValidationEvent> events = new CopyOnWriteArrayList<>();

        @EventListener
        void capture(CertificateValidationEvent event) {
            events.add(event);
        }

        void clear() {
            events.clear();
        }

        List<CertificateValidationEvent> getEvents() {
            return List.copyOf(events);
        }
    }

    @Autowired
    private CertificateExternalService certificateService;
    @Autowired
    private CertificateRepository certificateRepository;
    @Autowired
    private CertificateContentRepository certificateContentRepository;
    @Autowired
    private RaProfileRepository raProfileRepository;
    @Autowired
    private SettingsCache settingsCache;
    @Autowired
    private EventCaptor eventCaptor;

    @BeforeEach
    void setUp() {
        eventCaptor.clear();
        setPlatformValidationEnabled(true);
    }

    private Certificate buildCa() {
        X509CertificateEntity ca = aCertificate()
                .withFingerprint(UUID.randomUUID().toString())
                .withValidationStatus(CertificateValidationStatus.VALID)
                .withTrustedCa(false)
                .build();
        CertificateContent content = new CertificateContent();
        content.setFingerprint(UUID.randomUUID().toString());
        content.setContent("ca-content");
        content = certificateContentRepository.saveAndFlush(content);
        ca.setCertificateContentId(content.getId());
        return certificateRepository.saveAndFlush(ca);
    }

    private Certificate buildEligibleCert(Certificate issuer) {
        X509CertificateEntity cert = aCertificate()
                .withFingerprint(UUID.randomUUID().toString())
                .withValidationStatus(CertificateValidationStatus.VALID)
                .withArchived(false)
                .withIssuerCertificateUuid(issuer.getUuid())
                .build();
        CertificateContent content = new CertificateContent();
        content.setFingerprint(UUID.randomUUID().toString());
        content.setContent("cert-content");
        content = certificateContentRepository.saveAndFlush(content);
        cert.setCertificateContentId(content.getId());
        return certificateRepository.saveAndFlush(cert);
    }

    private Certificate buildCaWithStatus(CertificateValidationStatus status) {
        X509CertificateEntity ca = aCertificate()
                .withFingerprint(UUID.randomUUID().toString())
                .withValidationStatus(status)
                .withTrustedCa(false)
                .build();
        CertificateContent content = new CertificateContent();
        content.setFingerprint(UUID.randomUUID().toString());
        content.setContent("ca-content");
        content = certificateContentRepository.saveAndFlush(content);
        ca.setCertificateContentId(content.getId());
        return certificateRepository.saveAndFlush(ca);
    }

    private Certificate buildCaWithRaProfile(RaProfile raProfile) {
        X509CertificateEntity ca = aCertificate()
                .withFingerprint(UUID.randomUUID().toString())
                .withValidationStatus(CertificateValidationStatus.VALID)
                .withTrustedCa(false)
                .withRaProfileUuid(raProfile.getUuid())
                .build();
        CertificateContent content = new CertificateContent();
        content.setFingerprint(UUID.randomUUID().toString());
        content.setContent("ca-content");
        content = certificateContentRepository.saveAndFlush(content);
        ca.setCertificateContentId(content.getId());
        return certificateRepository.saveAndFlush(ca);
    }

    private RaProfile buildRaProfile(Boolean validationEnabled) {
        RaProfile rp = new RaProfile();
        rp.setName("rp-" + UUID.randomUUID());
        rp.setValidationEnabled(validationEnabled);
        return raProfileRepository.saveAndFlush(rp);
    }

    private void setPlatformValidationEnabled(boolean enabled) {
        CertificateValidationSettingsDto validation = new CertificateValidationSettingsDto();
        validation.setEnabled(enabled);
        CertificateSettingsDto certs = new CertificateSettingsDto();
        certs.setValidation(validation);
        PlatformSettingsDto platform = new PlatformSettingsDto();
        platform.setCertificates(certs);
        settingsCache.cacheSettings(SettingsSection.PLATFORM, platform);
    }

    private void callUpdateTrustedCa(UUID certUuid, boolean trustedCa)
            throws NotFoundException, CertificateOperationException, AttributeException {
        CertificateUpdateObjectsDto dto = new CertificateUpdateObjectsDto();
        dto.setTrustedCa(trustedCa);
        certificateService.updateCertificateObjects(SecuredUUID.fromUUID(certUuid), dto);
    }

    private CertificateValidationEvent capturePublishedEvent() {
        List<CertificateValidationEvent> events = eventCaptor.getEvents();
        assertThat(events).as("Expected exactly one CertificateValidationEvent to be published").hasSize(1);
        return events.getFirst();
    }

    private void verifyNoEventPublished() {
        assertThat(eventCaptor.getEvents()).as("Expected no CertificateValidationEvent to be published").isEmpty();
    }

    @Test
    void caWithEligibleDescendantsPublishesCaAndAllDescendants() throws Exception {
        // given
        X509CertificateEntity ca = X509CertificateEntity.from(buildCa());
        Certificate childA = buildEligibleCert(ca);
        Certificate childB = buildEligibleCert(ca);
        Certificate grandchild = buildEligibleCert(childB);

        // when
        callUpdateTrustedCa(ca.getUuid(), true);

        // then
        CertificateValidationEvent event = capturePublishedEvent();
        assertThat(event.certificateUuids())
                .containsExactlyInAnyOrder(ca.getUuid(), childA.getUuid(), childB.getUuid(), grandchild.getUuid());
        X509CertificateEntity updated = X509CertificateEntity
                .from(certificateRepository.findByUuid(ca.getUuid()).orElseThrow());
        assertThat(updated.getTrustedCa()).isTrue();
    }

    @Test
    void caWithNoDescendantsPublishesOnlyCa() throws Exception {
        // given
        X509CertificateEntity ca = X509CertificateEntity.from(buildCa());
        ca.setTrustedCa(true);
        certificateRepository.saveAndFlush(ca);

        // when
        callUpdateTrustedCa(ca.getUuid(), false);

        // then
        CertificateValidationEvent event = capturePublishedEvent();
        assertThat(event.certificateUuids()).containsExactly(ca.getUuid());
    }

    @Test
    void ineligibleDescendantsExcludedFromEvent() throws Exception {
        // given
        X509CertificateEntity ca = X509CertificateEntity.from(buildCa());
        Certificate eligible = buildEligibleCert(ca);

        X509CertificateEntity archived = aCertificate()
                .withFingerprint(UUID.randomUUID().toString())
                .withValidationStatus(CertificateValidationStatus.VALID)
                .withArchived(true)
                .withIssuerCertificateUuid(ca.getUuid())
                .build();
        CertificateContent c1 = new CertificateContent();
        c1.setFingerprint(UUID.randomUUID().toString());
        c1.setContent("c");
        archived.setCertificateContentId(certificateContentRepository.saveAndFlush(c1).getId());
        certificateRepository.saveAndFlush(archived);

        X509CertificateEntity noContent = aCertificate()
                .withFingerprint(UUID.randomUUID().toString())
                .withValidationStatus(CertificateValidationStatus.VALID)
                .withIssuerCertificateUuid(ca.getUuid())
                .build();
        certificateRepository.saveAndFlush(noContent);

        X509CertificateEntity revoked = aCertificate()
                .withFingerprint(UUID.randomUUID().toString())
                .withValidationStatus(CertificateValidationStatus.REVOKED)
                .withIssuerCertificateUuid(ca.getUuid())
                .build();
        CertificateContent c2 = new CertificateContent();
        c2.setFingerprint(UUID.randomUUID().toString());
        c2.setContent("c");
        revoked.setCertificateContentId(certificateContentRepository.saveAndFlush(c2).getId());
        certificateRepository.saveAndFlush(revoked);

        X509CertificateEntity expired = aCertificate()
                .withFingerprint(UUID.randomUUID().toString())
                .withValidationStatus(CertificateValidationStatus.EXPIRED)
                .withIssuerCertificateUuid(ca.getUuid())
                .build();
        CertificateContent c3 = new CertificateContent();
        c3.setFingerprint(UUID.randomUUID().toString());
        c3.setContent("c");
        expired.setCertificateContentId(certificateContentRepository.saveAndFlush(c3).getId());
        certificateRepository.saveAndFlush(expired);

        // when
        callUpdateTrustedCa(ca.getUuid(), true);

        // then
        CertificateValidationEvent event = capturePublishedEvent();
        assertThat(event.certificateUuids()).containsExactlyInAnyOrder(ca.getUuid(), eligible.getUuid());
    }

    @Test
    void unmarkingTrustTriggersRevalidation() throws Exception {
        // given
        X509CertificateEntity ca = X509CertificateEntity.from(buildCa());
        ca.setTrustedCa(true);
        certificateRepository.saveAndFlush(ca);
        Certificate child = buildEligibleCert(ca);

        // when
        callUpdateTrustedCa(ca.getUuid(), false);

        // then
        CertificateValidationEvent event = capturePublishedEvent();
        assertThat(event.certificateUuids()).containsExactlyInAnyOrder(ca.getUuid(), child.getUuid());
        X509CertificateEntity updated = X509CertificateEntity
                .from(certificateRepository.findByUuid(ca.getUuid()).orElseThrow());
        assertThat(updated.getTrustedCa()).isFalse();
    }

    @Test
    void archivedCaThrowsBeforePublishingEvent() {
        // given
        X509CertificateEntity ca = aCertificate()
                .withFingerprint(UUID.randomUUID().toString())
                .withValidationStatus(CertificateValidationStatus.VALID)
                .withTrustedCa(false)
                .withArchived(true)
                .build();
        certificateRepository.saveAndFlush(ca);

        // when / then
        UUID caUuid = ca.getUuid();
        assertThatThrownBy(() -> callUpdateTrustedCa(caUuid, true)).isInstanceOf(ValidationException.class);
        verifyNoEventPublished();
    }

    @Test
    void nonCaCertificateThrowsBeforePublishingEvent() {
        // given
        X509CertificateEntity cert = aCertificate()
                .withFingerprint(UUID.randomUUID().toString())
                .withValidationStatus(CertificateValidationStatus.VALID)
                .build();
        certificateRepository.saveAndFlush(cert);

        // when / then
        UUID certUuid = cert.getUuid();
        assertThatThrownBy(() -> callUpdateTrustedCa(certUuid, true)).isInstanceOf(ValidationException.class);
        verifyNoEventPublished();
    }

    @Test
    void caWithNoContentNotQueuedEligibleDescendantsStillAre() throws Exception {
        // given
        X509CertificateEntity ca = aCertificate()
                .withFingerprint(UUID.randomUUID().toString())
                .withValidationStatus(CertificateValidationStatus.VALID)
                .withTrustedCa(false)
                .build();
        ca = certificateRepository.saveAndFlush(ca);
        Certificate child = buildEligibleCert(ca);

        // when
        callUpdateTrustedCa(ca.getUuid(), true);

        // then
        CertificateValidationEvent event = capturePublishedEvent();
        assertThat(event.certificateUuids()).containsExactly(child.getUuid());
        assertThat(event.certificateUuids()).doesNotContain(ca.getUuid());
    }

    @Test
    void revokedCaNotQueuedEligibleDescendantsStillAre() throws Exception {
        // given
        X509CertificateEntity ca = X509CertificateEntity.from(buildCaWithStatus(CertificateValidationStatus.REVOKED));
        Certificate child = buildEligibleCert(ca);

        // when
        callUpdateTrustedCa(ca.getUuid(), true);

        // then
        CertificateValidationEvent event = capturePublishedEvent();
        assertThat(event.certificateUuids()).containsExactly(child.getUuid());
        assertThat(event.certificateUuids()).doesNotContain(ca.getUuid());
    }

    @Test
    void expiredCaNotQueuedEligibleDescendantsStillAre() throws Exception {
        // given
        X509CertificateEntity ca = X509CertificateEntity.from(buildCaWithStatus(CertificateValidationStatus.EXPIRED));
        Certificate child = buildEligibleCert(ca);

        // when
        callUpdateTrustedCa(ca.getUuid(), true);

        // then
        CertificateValidationEvent event = capturePublishedEvent();
        assertThat(event.certificateUuids()).containsExactly(child.getUuid());
        assertThat(event.certificateUuids()).doesNotContain(ca.getUuid());
    }

    @Test
    void caWithValidationDisabledRaProfileNotQueued() throws Exception {
        // given
        RaProfile disabledRp = buildRaProfile(false);
        X509CertificateEntity ca = X509CertificateEntity.from(buildCaWithRaProfile(disabledRp));
        Certificate child = buildEligibleCert(ca); // child has no RA profile → eligible

        // when
        callUpdateTrustedCa(ca.getUuid(), true);

        // then
        CertificateValidationEvent event = capturePublishedEvent();
        assertThat(event.certificateUuids()).containsExactly(child.getUuid());
        assertThat(event.certificateUuids()).doesNotContain(ca.getUuid());
    }

    @Test
    void noEventPublishedWhenCaAndAllDescendantsIneligible() throws Exception {
        // given — REVOKED CA, no descendants
        X509CertificateEntity ca = X509CertificateEntity.from(buildCaWithStatus(CertificateValidationStatus.REVOKED));

        // when
        callUpdateTrustedCa(ca.getUuid(), true);

        // then
        verifyNoEventPublished();
    }

    @Test
    void noEventPublishedWhenPlatformValidationDisabledAndNoCertsWithExplicitOptIn() throws Exception {
        // given — platform disabled; CA and child both inherit platform (no RA profile)
        setPlatformValidationEnabled(false);
        X509CertificateEntity ca = X509CertificateEntity.from(buildCa());
        buildEligibleCert(ca); // has no RA profile → inherits platform → excluded

        // when
        callUpdateTrustedCa(ca.getUuid(), true);

        // then
        verifyNoEventPublished();
    }

    @Test
    void noEventPublishedWhenTrustedCaMarkAlreadyTrue() throws Exception {
        // given — CA is already trusted; eligible descendant exists
        X509CertificateEntity ca = X509CertificateEntity.from(buildCa());
        ca.setTrustedCa(true);
        certificateRepository.saveAndFlush(ca);
        buildEligibleCert(ca);

        // when — request the same value
        callUpdateTrustedCa(ca.getUuid(), true);

        // then — early-return guard fires; no revalidation triggered
        verifyNoEventPublished();
    }

    @Test
    void noEventPublishedWhenTrustedCaMarkAlreadyFalse() throws Exception {
        // given — CA already has trustedCa=false (default from buildCa()); eligible descendant exists
        X509CertificateEntity ca = X509CertificateEntity.from(buildCa());
        buildEligibleCert(ca);

        // when — request the same value
        callUpdateTrustedCa(ca.getUuid(), false);

        // then — early-return guard fires; no revalidation triggered
        verifyNoEventPublished();
    }

    @Test
    void explicitRaProfileOptInOverridesPlatformDisabled() throws Exception {
        // given — platform disabled; CA and child both have RA profile with validationEnabled=true
        setPlatformValidationEnabled(false);
        RaProfile optInRp = buildRaProfile(true);
        X509CertificateEntity ca = X509CertificateEntity.from(buildCaWithRaProfile(optInRp));
        Certificate child = buildEligibleCert(ca);
        child.setRaProfileUuid(optInRp.getUuid());
        certificateRepository.saveAndFlush(child);

        // when
        callUpdateTrustedCa(ca.getUuid(), true);

        // then
        CertificateValidationEvent event = capturePublishedEvent();
        assertThat(event.certificateUuids()).containsExactlyInAnyOrder(ca.getUuid(), child.getUuid());
    }
}
