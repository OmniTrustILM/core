package com.czertainly.core.service.impl;

import com.czertainly.api.exception.AttributeException;
import com.czertainly.api.exception.CertificateOperationException;
import com.czertainly.api.exception.NotFoundException;
import com.czertainly.api.exception.ValidationException;
import com.czertainly.api.model.client.certificate.CertificateUpdateObjectsDto;
import com.czertainly.api.model.core.certificate.CertificateValidationStatus;
import com.czertainly.api.model.core.settings.CertificateSettingsDto;
import com.czertainly.api.model.core.settings.CertificateValidationSettingsDto;
import com.czertainly.api.model.core.settings.PlatformSettingsDto;
import com.czertainly.api.model.core.settings.SettingsSection;
import com.czertainly.core.dao.entity.Certificate;
import com.czertainly.core.dao.entity.CertificateContent;
import com.czertainly.core.dao.entity.RaProfile;
import com.czertainly.core.dao.repository.CertificateContentRepository;
import com.czertainly.core.dao.repository.CertificateRepository;
import com.czertainly.core.dao.repository.RaProfileRepository;
import com.czertainly.core.events.transaction.CertificateValidationEvent;
import com.czertainly.core.security.authz.SecuredUUID;
import com.czertainly.core.service.CertificateService;
import com.czertainly.core.settings.SettingsCache;
import com.czertainly.core.util.BaseSpringBootTest;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.context.annotation.Bean;
import org.springframework.context.event.EventListener;

import java.util.List;
import java.util.UUID;
import java.util.concurrent.CopyOnWriteArrayList;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class UpdateTrustedCaMarkTest extends BaseSpringBootTest {

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
    private CertificateService certificateService;
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
        Certificate ca = new Certificate();
        ca.setFingerprint(UUID.randomUUID().toString());
        ca.setValidationStatus(CertificateValidationStatus.VALID);
        ca.setTrustedCa(false);
        CertificateContent content = new CertificateContent();
        content.setFingerprint(UUID.randomUUID().toString());
        content.setContent("ca-content");
        content = certificateContentRepository.saveAndFlush(content);
        ca.setCertificateContentId(content.getId());
        return certificateRepository.saveAndFlush(ca);
    }

    private Certificate buildEligibleCert(Certificate issuer) {
        Certificate cert = new Certificate();
        cert.setFingerprint(UUID.randomUUID().toString());
        cert.setValidationStatus(CertificateValidationStatus.VALID);
        cert.setArchived(false);
        cert.setIssuerCertificateUuid(issuer.getUuid());
        CertificateContent content = new CertificateContent();
        content.setFingerprint(UUID.randomUUID().toString());
        content.setContent("cert-content");
        content = certificateContentRepository.saveAndFlush(content);
        cert.setCertificateContentId(content.getId());
        return certificateRepository.saveAndFlush(cert);
    }

    private Certificate buildCaWithStatus(CertificateValidationStatus status) {
        Certificate ca = new Certificate();
        ca.setFingerprint(UUID.randomUUID().toString());
        ca.setValidationStatus(status);
        ca.setTrustedCa(false);
        CertificateContent content = new CertificateContent();
        content.setFingerprint(UUID.randomUUID().toString());
        content.setContent("ca-content");
        content = certificateContentRepository.saveAndFlush(content);
        ca.setCertificateContentId(content.getId());
        return certificateRepository.saveAndFlush(ca);
    }

    private Certificate buildCaWithRaProfile(RaProfile raProfile) {
        Certificate ca = new Certificate();
        ca.setFingerprint(UUID.randomUUID().toString());
        ca.setValidationStatus(CertificateValidationStatus.VALID);
        ca.setTrustedCa(false);
        ca.setRaProfileUuid(raProfile.getUuid());
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
        assertThat(eventCaptor.getEvents())
                .as("Expected no CertificateValidationEvent to be published")
                .isEmpty();
    }

    @Test
    void caWithEligibleDescendantsPublishesCaAndAllDescendants() throws Exception {
        // given
        Certificate ca = buildCa();
        Certificate childA = buildEligibleCert(ca);
        Certificate childB = buildEligibleCert(ca);
        Certificate grandchild = buildEligibleCert(childB);

        // when
        callUpdateTrustedCa(ca.getUuid(), true);

        // then
        CertificateValidationEvent event = capturePublishedEvent();
        assertThat(event.certificateUuids())
                .containsExactlyInAnyOrder(ca.getUuid(), childA.getUuid(), childB.getUuid(), grandchild.getUuid());
        Certificate updated = certificateRepository.findByUuid(ca.getUuid()).orElseThrow();
        assertThat(updated.getTrustedCa()).isTrue();
    }

    @Test
    void caWithNoDescendantsPublishesOnlyCa() throws Exception {
        // given
        Certificate ca = buildCa();
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
        Certificate ca = buildCa();
        Certificate eligible = buildEligibleCert(ca);

        Certificate archived = new Certificate();
        archived.setFingerprint(UUID.randomUUID().toString());
        archived.setValidationStatus(CertificateValidationStatus.VALID);
        archived.setArchived(true);
        archived.setIssuerCertificateUuid(ca.getUuid());
        CertificateContent c1 = new CertificateContent();
        c1.setFingerprint(UUID.randomUUID().toString());
        c1.setContent("c");
        archived.setCertificateContentId(certificateContentRepository.saveAndFlush(c1).getId());
        certificateRepository.saveAndFlush(archived);

        Certificate noContent = new Certificate();
        noContent.setFingerprint(UUID.randomUUID().toString());
        noContent.setValidationStatus(CertificateValidationStatus.VALID);
        noContent.setIssuerCertificateUuid(ca.getUuid());
        certificateRepository.saveAndFlush(noContent);

        Certificate revoked = new Certificate();
        revoked.setFingerprint(UUID.randomUUID().toString());
        revoked.setValidationStatus(CertificateValidationStatus.REVOKED);
        revoked.setIssuerCertificateUuid(ca.getUuid());
        CertificateContent c2 = new CertificateContent();
        c2.setFingerprint(UUID.randomUUID().toString());
        c2.setContent("c");
        revoked.setCertificateContentId(certificateContentRepository.saveAndFlush(c2).getId());
        certificateRepository.saveAndFlush(revoked);

        Certificate expired = new Certificate();
        expired.setFingerprint(UUID.randomUUID().toString());
        expired.setValidationStatus(CertificateValidationStatus.EXPIRED);
        expired.setIssuerCertificateUuid(ca.getUuid());
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
        Certificate ca = buildCa();
        ca.setTrustedCa(true);
        certificateRepository.saveAndFlush(ca);
        Certificate child = buildEligibleCert(ca);

        // when
        callUpdateTrustedCa(ca.getUuid(), false);

        // then
        CertificateValidationEvent event = capturePublishedEvent();
        assertThat(event.certificateUuids()).containsExactlyInAnyOrder(ca.getUuid(), child.getUuid());
        Certificate updated = certificateRepository.findByUuid(ca.getUuid()).orElseThrow();
        assertThat(updated.getTrustedCa()).isFalse();
    }

    @Test
    void archivedCaThrowsBeforePublishingEvent() {
        // given
        Certificate ca = new Certificate();
        ca.setFingerprint(UUID.randomUUID().toString());
        ca.setValidationStatus(CertificateValidationStatus.VALID);
        ca.setTrustedCa(false);
        ca.setArchived(true);
        certificateRepository.saveAndFlush(ca);

        // when / then
        UUID caUuid = ca.getUuid();
        assertThatThrownBy(() -> callUpdateTrustedCa(caUuid, true))
                .isInstanceOf(ValidationException.class);
        verifyNoEventPublished();
    }

    @Test
    void nonCaCertificateThrowsBeforePublishingEvent() {
        // given
        Certificate cert = new Certificate();
        cert.setFingerprint(UUID.randomUUID().toString());
        cert.setValidationStatus(CertificateValidationStatus.VALID);
        certificateRepository.saveAndFlush(cert);

        // when / then
        UUID certUuid = cert.getUuid();
        assertThatThrownBy(() -> callUpdateTrustedCa(certUuid, true))
                .isInstanceOf(ValidationException.class);
        verifyNoEventPublished();
    }

    @Test
    void caWithNoContentNotQueuedEligibleDescendantsStillAre() throws Exception {
        // given
        Certificate ca = new Certificate();
        ca.setFingerprint(UUID.randomUUID().toString());
        ca.setValidationStatus(CertificateValidationStatus.VALID);
        ca.setTrustedCa(false);
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
        Certificate ca = buildCaWithStatus(CertificateValidationStatus.REVOKED);
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
        Certificate ca = buildCaWithStatus(CertificateValidationStatus.EXPIRED);
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
        Certificate ca = buildCaWithRaProfile(disabledRp);
        Certificate child = buildEligibleCert(ca);  // child has no RA profile → eligible

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
        Certificate ca = buildCaWithStatus(CertificateValidationStatus.REVOKED);

        // when
        callUpdateTrustedCa(ca.getUuid(), true);

        // then
        verifyNoEventPublished();
    }

    @Test
    void noEventPublishedWhenPlatformValidationDisabledAndNoCertsWithExplicitOptIn() throws Exception {
        // given — platform disabled; CA and child both inherit platform (no RA profile)
        setPlatformValidationEnabled(false);
        Certificate ca = buildCa();
        buildEligibleCert(ca);  // has no RA profile → inherits platform → excluded

        // when
        callUpdateTrustedCa(ca.getUuid(), true);

        // then
        verifyNoEventPublished();
    }

    @Test
    void noEventPublishedWhenTrustedCaMarkAlreadyTrue() throws Exception {
        // given — CA is already trusted; eligible descendant exists
        Certificate ca = buildCa();
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
        Certificate ca = buildCa();
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
        Certificate ca = buildCaWithRaProfile(optInRp);
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
