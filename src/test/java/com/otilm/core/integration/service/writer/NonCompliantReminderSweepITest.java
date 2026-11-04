package com.otilm.core.integration.service.writer;

import com.otilm.api.model.core.auth.Resource;
import com.otilm.api.model.core.certificate.CertificateRelationType;
import com.otilm.api.model.core.certificate.CertificateState;
import com.otilm.api.model.core.certificate.CertificateValidationStatus;
import com.otilm.api.model.core.compliance.ComplianceStatus;
import com.otilm.api.model.core.notification.RecipientType;
import com.otilm.api.model.core.other.ResourceEvent;
import com.otilm.core.dao.entity.Certificate;
import com.otilm.core.dao.entity.CertificateRelation;
import com.otilm.core.dao.entity.notifications.NotificationProfile;
import com.otilm.core.dao.entity.notifications.NotificationProfileVersion;
import com.otilm.core.dao.entity.notifications.PendingNotification;
import com.otilm.core.dao.repository.CertificateRelationRepository;
import com.otilm.core.dao.repository.CertificateRepository;
import com.otilm.core.dao.repository.notifications.NotificationProfileRepository;
import com.otilm.core.dao.repository.notifications.NotificationProfileVersionRepository;
import com.otilm.core.dao.repository.notifications.PendingNotificationRepository;
import com.otilm.core.service.writer.PendingNotificationWriter;
import com.otilm.core.util.BaseSpringBootTest;
import com.otilm.core.util.builders.CertificateBuilder;
import java.time.Duration;
import java.time.OffsetDateTime;
import java.util.Arrays;
import java.util.List;
import java.util.UUID;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.transaction.support.TransactionTemplate;

import static com.otilm.core.util.builders.CertificateBuilder.aCertificate;
import static org.assertj.core.api.Assertions.assertThat;

class NonCompliantReminderSweepITest extends BaseSpringBootTest {

    private static final ResourceEvent EVENT = ResourceEvent.CERTIFICATE_NOT_COMPLIANT;

    @Autowired
    private CertificateRepository certificateRepository;
    @Autowired
    private CertificateRelationRepository certificateRelationRepository;
    @Autowired
    private NotificationProfileRepository notificationProfileRepository;
    @Autowired
    private NotificationProfileVersionRepository notificationProfileVersionRepository;
    @Autowired
    private PendingNotificationRepository pendingNotificationRepository;
    @Autowired
    private PendingNotificationWriter pendingNotificationWriter;
    @Autowired
    private TransactionTemplate transactionTemplate;

    @Test
    void selectsEligibleCertificates_whenProfilesEnableReminders() {
        // given
        UUID reminding = createReminderProfile(null, 3);
        UUID notifyingOnce = createReminderProfile(null, null);

        Certificate eligible = createCertificate(aCertificate().withComplianceStatus(ComplianceStatus.NOK));
        Certificate profileWithoutReminders = createCertificate(
                aCertificate().withComplianceStatus(ComplianceStatus.NOK));
        Certificate compliant = createCertificate(aCertificate().withComplianceStatus(ComplianceStatus.OK));
        Certificate archived = createCertificate(
                aCertificate().withComplianceStatus(ComplianceStatus.NOK).withArchived(true));
        Certificate revoked = createCertificate(
                aCertificate().withComplianceStatus(ComplianceStatus.NOK).withState(CertificateState.REVOKED));
        Certificate expired = createCertificate(aCertificate()
                .withComplianceStatus(ComplianceStatus.NOK)
                .withValidationStatus(CertificateValidationStatus.EXPIRED));
        Certificate exhausted = createCertificate(aCertificate().withComplianceStatus(ComplianceStatus.NOK));

        recordSends(reminding, eligible, 1);
        recordSends(notifyingOnce, profileWithoutReminders, 1);
        recordSends(reminding, compliant, 1);
        recordSends(reminding, archived, 1);
        recordSends(reminding, revoked, 1);
        recordSends(reminding, expired, 1);
        recordSends(reminding, exhausted, 3);

        // when
        List<UUID> due = findDueCertificates(eligible, profileWithoutReminders, compliant, archived, revoked, expired,
                exhausted);

        // then
        assertThat(due).containsExactly(eligible.getUuid());
    }

    @Test
    void selectsCertificate_whenFrequencyHasElapsed() {
        // given
        UUID profile = createReminderProfile(Duration.ofHours(1), null);
        Certificate elapsed = createCertificate(aCertificate().withComplianceStatus(ComplianceStatus.NOK));
        Certificate notElapsed = createCertificate(aCertificate().withComplianceStatus(ComplianceStatus.NOK));
        recordSendAt(profile, elapsed, 1, OffsetDateTime.now().minusHours(2));
        recordSendAt(profile, notElapsed, 1, OffsetDateTime.now().minusMinutes(30));

        // when
        List<UUID> due = findDueCertificates(elapsed, notElapsed);

        // then
        assertThat(due).containsExactly(elapsed.getUuid());
    }

    @Test
    void usesTheProfileVersionTheRowIsPinnedTo_whenSelectingReminders() {
        // given
        UUID profile = createReminderProfile(null, 3);
        addProfileVersion(profile, 2, null, null);
        Certificate pinnedToReminding = createCertificate(aCertificate().withComplianceStatus(ComplianceStatus.NOK));
        Certificate pinnedToNotifyingOnce = createCertificate(
                aCertificate().withComplianceStatus(ComplianceStatus.NOK));
        recordSendAt(profile, pinnedToReminding, 1, OffsetDateTime.now().minusDays(1));
        recordSendAt(profile, pinnedToNotifyingOnce, 2, OffsetDateTime.now().minusDays(1));

        // when
        List<UUID> due = findDueCertificates(pinnedToReminding, pinnedToNotifyingOnce);

        // then
        assertThat(due).containsExactly(pinnedToReminding.getUuid());
    }

    @Test
    void excludesCertificatesWithIssuedRenewal_whenSelectingReminders() {
        // given
        UUID reminding = createReminderProfile(null, 5);
        Certificate renewed = createCertificate(aCertificate().withComplianceStatus(ComplianceStatus.NOK));
        Certificate failedRenewal = createCertificate(aCertificate().withComplianceStatus(ComplianceStatus.NOK));
        recordSends(reminding, renewed, 1);
        recordSends(reminding, failedRenewal, 1);
        linkRenewal(renewed, createCertificate(aCertificate().withComplianceStatus(ComplianceStatus.OK)));
        linkRenewal(failedRenewal, createCertificate(
                aCertificate().withComplianceStatus(ComplianceStatus.OK).withState(CertificateState.FAILED)));

        // when
        List<UUID> due = findDueCertificates(renewed, failedRenewal);

        // then
        assertThat(due).containsExactly(failedRenewal.getUuid());
    }

    @Test
    void deletesOnlyMatchingRows_whenResettingAnObjectEvent() {
        // given
        UUID profile = createReminderProfile(null, 5);
        Certificate target = createCertificate(aCertificate());
        Certificate other = createCertificate(aCertificate());
        recordSends(profile, target, 1);
        recordSends(profile, other, 1);
        recordSend(profile, target, ResourceEvent.CERTIFICATE_EXPIRING);

        // when
        pendingNotificationWriter.deleteForObjectAndEvent(Resource.CERTIFICATE, target.getUuid(), EVENT);

        // then
        assertThat(findRow(profile, target, EVENT)).isNull();
        assertThat(findRow(profile, target, ResourceEvent.CERTIFICATE_EXPIRING)).isNotNull();
        assertThat(findRow(profile, other, EVENT)).isNotNull();
    }

    @Test
    void deletesRowsOfEveryEvent_whenDeletingForAnObject() {
        // given
        UUID profile = createReminderProfile(null, 5);
        Certificate deleted = createCertificate(aCertificate());
        Certificate kept = createCertificate(aCertificate());
        recordRowsForEveryEvent(profile, deleted, kept);

        // when
        pendingNotificationWriter.deleteForObject(Resource.CERTIFICATE, deleted.getUuid());

        // then
        assertThat(findRow(profile, deleted, EVENT)).isNull();
        assertThat(findRow(profile, deleted, ResourceEvent.CERTIFICATE_EXPIRING)).isNull();
        assertThat(findRow(profile, kept, EVENT)).isNotNull();
        assertThat(findRow(profile, kept, ResourceEvent.CERTIFICATE_EXPIRING)).isNotNull();
    }

    @Test
    void deletesRowsOfEveryEvent_whenDeletingForSeveralObjects() {
        // given
        UUID profile = createReminderProfile(null, 5);
        Certificate firstDeleted = createCertificate(aCertificate());
        Certificate secondDeleted = createCertificate(aCertificate());
        Certificate kept = createCertificate(aCertificate());
        recordRowsForEveryEvent(profile, firstDeleted, secondDeleted, kept);

        // when
        pendingNotificationWriter
                .deleteForObjects(Resource.CERTIFICATE, List.of(firstDeleted.getUuid(), secondDeleted.getUuid()));

        // then
        for (Certificate deleted : List.of(firstDeleted, secondDeleted)) {
            assertThat(findRow(profile, deleted, EVENT)).isNull();
            assertThat(findRow(profile, deleted, ResourceEvent.CERTIFICATE_EXPIRING)).isNull();
        }
        assertThat(findRow(profile, kept, EVENT)).isNotNull();
        assertThat(findRow(profile, kept, ResourceEvent.CERTIFICATE_EXPIRING)).isNotNull();
    }

    @Test
    void deletesNothing_whenDeletingForNoObjects() {
        // given
        UUID profile = createReminderProfile(null, 5);
        Certificate certificate = createCertificate(aCertificate());
        recordRowsForEveryEvent(profile, certificate);

        // when
        pendingNotificationWriter.deleteForObjects(Resource.CERTIFICATE, List.of());

        // then
        assertThat(findRow(profile, certificate, EVENT)).isNotNull();
        assertThat(findRow(profile, certificate, ResourceEvent.CERTIFICATE_EXPIRING)).isNotNull();
    }

    // ── Helpers ───────────────────────────────────────────────────────────────

    private List<UUID> findDueCertificates(Certificate... candidates) {
        List<UUID> candidateUuids = Arrays.stream(candidates).map(Certificate::getUuid).toList();
        return certificateRepository
                .findNonCompliantCertificatesWithReminders(OffsetDateTime.now())
                .stream()
                .filter(candidateUuids::contains)
                .toList();
    }

    private UUID createReminderProfile(Duration frequency, Integer repetitions) {
        NotificationProfile profile = new NotificationProfile();
        profile.setName("reminder-profile-" + UUID.randomUUID());
        profile = notificationProfileRepository.save(profile);
        addProfileVersion(profile.getUuid(), 1, frequency, repetitions);
        return profile.getUuid();
    }

    private void addProfileVersion(UUID profileUuid, int versionNumber, Duration frequency, Integer repetitions) {
        NotificationProfileVersion version = new NotificationProfileVersion();
        version.setNotificationProfileUuid(profileUuid);
        version.setVersion(versionNumber);
        version.setRecipientType(RecipientType.NONE);
        version.setInternalNotification(false);
        version.setFrequency(frequency);
        version.setRepetitions(repetitions);
        notificationProfileVersionRepository.save(version);
    }

    private void recordSendAt(UUID profileUuid, Certificate certificate, int pinnedVersion, OffsetDateTime sentAt) {
        transactionTemplate
                .executeWithoutResult(status -> pendingNotificationRepository
                        .upsertSent(UUID.randomUUID(), profileUuid, Resource.CERTIFICATE.name(), certificate.getUuid(),
                                EVENT.name(), pinnedVersion, sentAt));
    }

    private Certificate createCertificate(CertificateBuilder builder) {
        Certificate certificate = builder
                .withSubjectDn("CN=" + UUID.randomUUID())
                .withIssuerDn("CN=issuer")
                .withSerialNumber(UUID.randomUUID().toString())
                .build();
        if (certificate.getState() == null) {
            certificate.setState(CertificateState.ISSUED);
        }
        return certificateRepository.save(certificate);
    }

    private void recordSends(UUID profileUuid, Certificate certificate, int count) {
        for (int i = 0; i < count; i++) {
            recordSend(profileUuid, certificate, EVENT);
        }
    }

    private void recordSend(UUID profileUuid, Certificate certificate, ResourceEvent event) {
        pendingNotificationWriter.recordSent(profileUuid, Resource.CERTIFICATE, certificate.getUuid(), event, 1);
    }

    private void recordRowsForEveryEvent(UUID profileUuid, Certificate... certificates) {
        for (Certificate certificate : certificates) {
            recordSend(profileUuid, certificate, EVENT);
            recordSend(profileUuid, certificate, ResourceEvent.CERTIFICATE_EXPIRING);
        }
    }

    private PendingNotification findRow(UUID profileUuid, Certificate certificate, ResourceEvent event) {
        return pendingNotificationRepository
                .findByNotificationProfileUuidAndResourceAndObjectUuidAndEvent(profileUuid, Resource.CERTIFICATE,
                        certificate.getUuid(), event);
    }

    private void linkRenewal(Certificate predecessor, Certificate successor) {
        CertificateRelation relation = new CertificateRelation();
        relation.setPredecessorCertificate(predecessor);
        relation.setSuccessorCertificate(successor);
        relation.setRelationType(CertificateRelationType.REPLACEMENT);
        certificateRelationRepository.save(relation);
    }
}
