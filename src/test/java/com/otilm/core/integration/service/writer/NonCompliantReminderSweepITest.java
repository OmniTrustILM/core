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
import com.otilm.core.dao.repository.CertificateRelationRepository;
import com.otilm.core.dao.repository.CertificateRepository;
import com.otilm.core.dao.repository.notifications.NotificationProfileRepository;
import com.otilm.core.dao.repository.notifications.NotificationProfileVersionRepository;
import com.otilm.core.dao.repository.notifications.PendingNotificationRepository;
import com.otilm.core.service.writer.PendingNotificationWriter;
import com.otilm.core.util.BaseSpringBootTest;
import java.time.Duration;
import java.util.Arrays;
import java.util.List;
import java.util.UUID;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;

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

    @Test
    void selectsOnlyNonCompliantCertificatesWhoseProfileReminds() {
        UUID reminding = remindingProfile(Duration.ofDays(1), 3);
        UUID once = remindingProfile(null, null);

        Certificate selected = certificate(ComplianceStatus.NOK, CertificateState.ISSUED, false);
        Certificate withoutReminders = certificate(ComplianceStatus.NOK, CertificateState.ISSUED, false);
        Certificate compliant = certificate(ComplianceStatus.OK, CertificateState.ISSUED, false);
        Certificate archived = certificate(ComplianceStatus.NOK, CertificateState.ISSUED, true);
        Certificate revoked = certificate(ComplianceStatus.NOK, CertificateState.REVOKED, false);
        Certificate exhausted = certificate(ComplianceStatus.NOK, CertificateState.ISSUED, false);
        Certificate expired = certificate(ComplianceStatus.NOK, CertificateState.ISSUED, false);
        expired.setValidationStatus(CertificateValidationStatus.EXPIRED);
        certificateRepository.save(expired);

        sent(reminding, selected, 1);
        sent(once, withoutReminders, 1);
        sent(reminding, compliant, 1);
        sent(reminding, archived, 1);
        sent(reminding, revoked, 1);
        sent(reminding, exhausted, 3);
        sent(reminding, expired, 1);

        List<UUID> due = due(selected, withoutReminders, compliant, archived, revoked, exhausted, expired);

        Assertions.assertEquals(List.of(selected.getUuid()), due);
    }

    @Test
    void skipsCertificatesWithAnIssuedRenewalButNotWithAFailedOne() {
        UUID reminding = remindingProfile(null, 5);
        Certificate renewed = certificate(ComplianceStatus.NOK, CertificateState.ISSUED, false);
        Certificate failedRenewal = certificate(ComplianceStatus.NOK, CertificateState.ISSUED, false);
        sent(reminding, renewed, 1);
        sent(reminding, failedRenewal, 1);

        relate(renewed, certificate(ComplianceStatus.OK, CertificateState.ISSUED, false));
        relate(failedRenewal, certificate(ComplianceStatus.OK, CertificateState.FAILED, false));

        List<UUID> due = due(renewed, failedRenewal);

        Assertions.assertEquals(List.of(failedRenewal.getUuid()), due);
    }

    @Test
    void resetRemovesOnlyTheRowsOfThatObjectAndEvent() {
        UUID profile = remindingProfile(null, 5);
        Certificate target = certificate(ComplianceStatus.NOK, CertificateState.ISSUED, false);
        Certificate other = certificate(ComplianceStatus.NOK, CertificateState.ISSUED, false);
        sent(profile, target, 1);
        sent(profile, other, 1);
        pendingNotificationWriter
                .recordSent(profile, Resource.CERTIFICATE, target.getUuid(), ResourceEvent.CERTIFICATE_EXPIRING, 1);

        pendingNotificationWriter.deleteForObjectAndEvent(Resource.CERTIFICATE, target.getUuid(), EVENT);

        Assertions
                .assertNull(pendingNotificationRepository
                        .findByNotificationProfileUuidAndResourceAndObjectUuidAndEvent(profile, Resource.CERTIFICATE,
                                target.getUuid(), EVENT));
        Assertions
                .assertNotNull(pendingNotificationRepository
                        .findByNotificationProfileUuidAndResourceAndObjectUuidAndEvent(profile, Resource.CERTIFICATE,
                                target.getUuid(), ResourceEvent.CERTIFICATE_EXPIRING));
        Assertions
                .assertNotNull(pendingNotificationRepository
                        .findByNotificationProfileUuidAndResourceAndObjectUuidAndEvent(profile, Resource.CERTIFICATE,
                                other.getUuid(), EVENT));
    }

    @Test
    void deletingObjectsRemovesTheirRowsForEveryEvent() {
        UUID profile = remindingProfile(null, 5);
        Certificate first = certificate(ComplianceStatus.NOK, CertificateState.ISSUED, false);
        Certificate second = certificate(ComplianceStatus.NOK, CertificateState.ISSUED, false);
        Certificate kept = certificate(ComplianceStatus.NOK, CertificateState.ISSUED, false);
        for (Certificate certificate : List.of(first, second, kept)) {
            sent(profile, certificate, 1);
            pendingNotificationWriter
                    .recordSent(profile, Resource.CERTIFICATE, certificate.getUuid(),
                            ResourceEvent.CERTIFICATE_EXPIRING, 1);
        }

        pendingNotificationWriter.deleteForObject(Resource.CERTIFICATE, first.getUuid());
        pendingNotificationWriter.deleteForObjects(Resource.CERTIFICATE, List.of(second.getUuid()));
        pendingNotificationWriter.deleteForObjects(Resource.CERTIFICATE, List.of());

        Assertions
                .assertNull(pendingNotificationRepository
                        .findByNotificationProfileUuidAndResourceAndObjectUuidAndEvent(profile, Resource.CERTIFICATE,
                                second.getUuid(), ResourceEvent.CERTIFICATE_EXPIRING));
        Assertions
                .assertNotNull(pendingNotificationRepository
                        .findByNotificationProfileUuidAndResourceAndObjectUuidAndEvent(profile, Resource.CERTIFICATE,
                                kept.getUuid(), ResourceEvent.CERTIFICATE_EXPIRING));
        Assertions
                .assertNotNull(pendingNotificationRepository
                        .findByNotificationProfileUuidAndResourceAndObjectUuidAndEvent(profile, Resource.CERTIFICATE,
                                kept.getUuid(), EVENT));
    }

    private List<UUID> due(Certificate... candidates) {
        List<UUID> candidateUuids = Arrays.stream(candidates).map(Certificate::getUuid).toList();
        return certificateRepository
                .findNonCompliantCertificatesWithReminders()
                .stream()
                .filter(candidateUuids::contains)
                .toList();
    }

    private UUID remindingProfile(Duration frequency, Integer repetitions) {
        NotificationProfile profile = new NotificationProfile();
        profile.setName("reminder-profile-" + UUID.randomUUID());
        profile = notificationProfileRepository.save(profile);

        NotificationProfileVersion version = new NotificationProfileVersion();
        version.setNotificationProfileUuid(profile.getUuid());
        version.setVersion(1);
        version.setRecipientType(RecipientType.NONE);
        version.setInternalNotification(false);
        version.setFrequency(frequency);
        version.setRepetitions(repetitions);
        notificationProfileVersionRepository.save(version);
        return profile.getUuid();
    }

    private Certificate certificate(ComplianceStatus compliance, CertificateState state, boolean archived) {
        Certificate certificate = new Certificate();
        certificate.setSubjectDn("CN=" + UUID.randomUUID());
        certificate.setIssuerDn("CN=issuer");
        certificate.setSerialNumber(UUID.randomUUID().toString());
        certificate.setComplianceStatus(compliance);
        certificate.setState(state);
        certificate.setArchived(archived);
        return certificateRepository.save(certificate);
    }

    private void sent(UUID profileUuid, Certificate certificate, int repetitions) {
        for (int i = 0; i < repetitions; i++) {
            pendingNotificationWriter.recordSent(profileUuid, Resource.CERTIFICATE, certificate.getUuid(), EVENT, 1);
        }
    }

    private void relate(Certificate predecessor, Certificate successor) {
        CertificateRelation relation = new CertificateRelation();
        relation.setPredecessorCertificate(predecessor);
        relation.setSuccessorCertificate(successor);
        relation.setRelationType(CertificateRelationType.REPLACEMENT);
        certificateRelationRepository.save(relation);
    }
}
