package com.czertainly.core.tasks;

import com.czertainly.api.model.client.connector.v2.ConnectorVersion;
import com.czertainly.api.model.core.certificate.CertificateRelationType;
import com.czertainly.api.model.core.certificate.CertificateState;
import com.czertainly.api.model.core.certificate.CertificateValidationStatus;
import com.czertainly.api.model.core.connector.ConnectorStatus;
import com.czertainly.api.model.core.raprofile.RaProfileCertificateValidationSettingsUpdateDto;
import com.czertainly.api.model.core.settings.CertificateSettingsDto;
import com.czertainly.api.model.core.settings.CertificateValidationSettingsDto;
import com.czertainly.api.model.core.settings.PlatformSettingsDto;
import com.czertainly.api.model.core.settings.SettingsSection;
import com.czertainly.api.model.scheduler.SchedulerJobExecutionStatus;
import com.czertainly.core.dao.entity.*;
import com.czertainly.core.dao.entity.acme.AcmeNonce;
import com.czertainly.core.dao.repository.*;
import com.czertainly.core.dao.repository.acme.AcmeNonceRepository;
import com.czertainly.core.messaging.jms.listeners.ValidationListener;
import com.czertainly.core.messaging.jms.producers.ValidationProducer;
import com.czertainly.core.messaging.model.ValidationMessage;
import com.czertainly.core.model.ScheduledTaskResult;
import com.czertainly.core.service.CertificateService;
import com.czertainly.core.service.SettingService;
import com.czertainly.core.settings.SettingsCache;
import com.czertainly.core.util.BaseSpringBootTest;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.context.bean.override.mockito.MockitoSpyBean;

import java.time.OffsetDateTime;
import java.util.Date;
import java.util.List;

import static org.mockito.ArgumentMatchers.any;

class UpdateCertificateStatusTaskTest extends BaseSpringBootTest {

    @Autowired
    private CertificateRepository certificateRepository;
    @Autowired
    private CertificateContentRepository certificateContentRepository;
    @Autowired
    private ConnectorRepository connectorRepository;
    @Autowired
    private RaProfileRepository raProfileRepository;
    @Autowired
    private AuthorityInstanceReferenceRepository authorityInstanceReferenceRepository;
    @Autowired
    private CertificateRelationRepository certificateRelationRepository;
    @Autowired
    private AcmeNonceRepository acmeNonceRepository;

    @Autowired
    private SettingsCache settingsCache;
    @Autowired
    private SettingService settingService;

    @MockitoBean
    private ValidationProducer validationProducer;

    @Autowired
    private UpdateCertificateStatusTask updateCertificateStatusTask;

    @Autowired
    private ValidationListener validationListener;

    @MockitoSpyBean
    private CertificateService mockedCertificateService;

    private ScheduledJobInfo scheduledJobInfo;

    Certificate notValidatedCert;
    Certificate alreadyValidatedCert;
    Certificate certToRevalidate;
    Certificate certToRevalidate2;

    @BeforeEach
    void setUp() {
        scheduledJobInfo = new ScheduledJobInfo("updateCertificateStatusJob");

        // A certificate with status expired
        Certificate expiredStatusCert = new Certificate();
        expiredStatusCert.setStatusValidationTimestamp(null);
        setCertificateContent(expiredStatusCert);
        expiredStatusCert.setValidationStatus(CertificateValidationStatus.EXPIRED);
        certificateRepository.save(expiredStatusCert);

        // A certificate which has not been validated yet
        notValidatedCert = new Certificate();
        notValidatedCert.setStatusValidationTimestamp(null);
        setCertificateContent(notValidatedCert);
        notValidatedCert.setValidationStatus(CertificateValidationStatus.NOT_CHECKED);
        certificateRepository.save(notValidatedCert);

        // A certificate which has been validated in the last day
        alreadyValidatedCert = new Certificate();
        alreadyValidatedCert.setStatusValidationTimestamp(OffsetDateTime.now());
        setCertificateContent(alreadyValidatedCert);
        alreadyValidatedCert.setValidationStatus(CertificateValidationStatus.INVALID);
        certificateRepository.save(alreadyValidatedCert);

        // A certificate which has been validated later than before one day
        certToRevalidate = new Certificate();
        certToRevalidate.setStatusValidationTimestamp(OffsetDateTime.now().minusHours(25));
        setCertificateContent(certToRevalidate);
        certToRevalidate.setValidationStatus(CertificateValidationStatus.INVALID);
        certificateRepository.save(certToRevalidate);


        // A certificate which has been validated later than before two days
        certToRevalidate2 = new Certificate();
        certToRevalidate2.setStatusValidationTimestamp(OffsetDateTime.now().minusDays(3));
        setCertificateContent(certToRevalidate2);
        certToRevalidate2.setValidationStatus(CertificateValidationStatus.INVALID);
        certificateRepository.save(certToRevalidate2);

        Certificate archivedCertificate = new Certificate();
        archivedCertificate.setArchived(true);
        setCertificateContent(archivedCertificate);
        archivedCertificate.setValidationStatus(CertificateValidationStatus.NOT_CHECKED);
        certificateRepository.save(archivedCertificate);

        Mockito.doAnswer(execution -> {
            Certificate certificate = execution.getArgument(0);
            certificate.setStatusValidationTimestamp(OffsetDateTime.now());
            certificateRepository.save(certificate);
            return null;
        }).when(mockedCertificateService).validate(any());

        Mockito.doAnswer(invocation -> {
            Object msg = invocation.getArgument(0);
            validationListener.processMessage((ValidationMessage) msg);
            return null; // because produceMessage returns void
        }).when(validationProducer).produceMessage(Mockito.any());

    }



    @Test
    void testCertificatesValidationDefaultSettings() {
        OffsetDateTime timeNow = OffsetDateTime.now();
        updateCertificateStatusTask.performJob(scheduledJobInfo, null);
        // Should validate notValidatedCert, certToRevalidate and certToRevalidate2
        assertCorrectCertificatesHaveBeenValidated(List.of(notValidatedCert, certToRevalidate2, certToRevalidate2), timeNow);
    }

    @Test
    void testCertificateValidationCustomSettings() {
        PlatformSettingsDto platformSettingsDto = getPlatformSettingsDto(true);
        settingsCache.cacheSettings(SettingsSection.PLATFORM, platformSettingsDto);
        OffsetDateTime timeNow = OffsetDateTime.now();
        updateCertificateStatusTask.performJob(scheduledJobInfo, null);
        // Should validate notValidatedCert and certToRevalidate2
        settingsCache.cacheSettings(SettingsSection.PLATFORM,settingService.getPlatformSettings());
        assertCorrectCertificatesHaveBeenValidated(List.of(notValidatedCert, certToRevalidate2), timeNow);
    }

    private PlatformSettingsDto getPlatformSettingsDto(boolean validationEnabled) {
        PlatformSettingsDto platformSettingsDto = new PlatformSettingsDto();
        CertificateSettingsDto certificateSettingsDto = new CertificateSettingsDto();
        CertificateValidationSettingsDto certificateValidationSettingsDto = new CertificateValidationSettingsDto();
        certificateValidationSettingsDto.setEnabled(validationEnabled);
        certificateValidationSettingsDto.setFrequency(2);
        certificateSettingsDto.setValidation(certificateValidationSettingsDto);
        platformSettingsDto.setCertificates(certificateSettingsDto);
        return platformSettingsDto;
    }

    @Test
    void testValidationWithCertificatesWithRaProfile() {
        RaProfileCertificateValidationSettingsUpdateDto validationUpdateDto = new RaProfileCertificateValidationSettingsUpdateDto();

        // Certificate which has RA Profile with validation disabled
        Certificate certificateWithRaProfileValidationDisabled = new Certificate();
        certificateWithRaProfileValidationDisabled.setStatusValidationTimestamp(OffsetDateTime.now().minusDays(2));
        validationUpdateDto.setEnabled(false);
        certificateWithRaProfileValidationDisabled.setRaProfile(getRaProfile(validationUpdateDto));
        setCertificateContent(certificateWithRaProfileValidationDisabled);
        certificateWithRaProfileValidationDisabled.setValidationStatus(CertificateValidationStatus.INVALID);
        certificateRepository.save(certificateWithRaProfileValidationDisabled);

        // Certificate which has RA Profile with validation enabled and default settings
        Certificate certificateWithRaProfileValidationEnabledDefault = new Certificate();
        certificateWithRaProfileValidationEnabledDefault.setStatusValidationTimestamp(null);
        validationUpdateDto.setEnabled(true);
        certificateWithRaProfileValidationEnabledDefault.setRaProfile(getRaProfile(validationUpdateDto));
        setCertificateContent(certificateWithRaProfileValidationEnabledDefault);
        certificateWithRaProfileValidationEnabledDefault.setValidationStatus(CertificateValidationStatus.INVALID);
        certificateRepository.save(certificateWithRaProfileValidationEnabledDefault);

        // Certificate which has RA Profile with validation enabled and custom settings
        Certificate certificateWithRaProfileValidationEnabledCustom = new Certificate();
        certificateWithRaProfileValidationEnabledCustom.setStatusValidationTimestamp(null);
        validationUpdateDto.setFrequency(2);
        certificateWithRaProfileValidationEnabledCustom.setRaProfile(getRaProfile(validationUpdateDto));
        setCertificateContent(certificateWithRaProfileValidationEnabledCustom);
        certificateWithRaProfileValidationEnabledCustom.setValidationStatus(CertificateValidationStatus.VALID);
        certificateRepository.save(certificateWithRaProfileValidationEnabledCustom);

        // Certificate which has RA Profile with enabled set to null
        Certificate certificateWithRaProfileValidationEnabledNull = new Certificate();
        certificateWithRaProfileValidationEnabledNull.setValidationStatus(null);
        validationUpdateDto.setEnabled(null);
        certificateWithRaProfileValidationEnabledNull.setRaProfile(getRaProfile(validationUpdateDto));
        setCertificateContent(certificateWithRaProfileValidationEnabledNull);
        certificateWithRaProfileValidationEnabledNull.setValidationStatus(CertificateValidationStatus.VALID);
        certificateRepository.save(certificateWithRaProfileValidationEnabledNull);

        OffsetDateTime timeNow = OffsetDateTime.now();
        updateCertificateStatusTask.performJob(scheduledJobInfo, null);
        // Should validate notValidatedCert, certToRevalidate, certToRevalidate2, certificateWithRaProfileValidationEnabledDefault and certificateWithRaProfileValidationEnabledCustom
        assertCorrectCertificatesHaveBeenValidated(List.of(notValidatedCert, certToRevalidate2, certToRevalidate, certificateWithRaProfileValidationEnabledDefault, certificateWithRaProfileValidationEnabledCustom, certificateWithRaProfileValidationEnabledNull), timeNow);

        settingsCache.cacheSettings(SettingsSection.PLATFORM, getPlatformSettingsDto(false));
        certificateWithRaProfileValidationEnabledDefault.setStatusValidationTimestamp(OffsetDateTime.now().minusDays(10));
        certificateWithRaProfileValidationEnabledCustom.setStatusValidationTimestamp(OffsetDateTime.now().minusDays(10));
        certificateRepository.save(certificateWithRaProfileValidationEnabledCustom);
        certificateRepository.save(certificateWithRaProfileValidationEnabledDefault);

        timeNow = OffsetDateTime.now();
        updateCertificateStatusTask.performJob(scheduledJobInfo, null);
        // Should validate certificateWithRaProfileValidationEnabledDefault and certificateWithRaProfileValidationEnabledCustom
        assertCorrectCertificatesHaveBeenValidated(List.of(certificateWithRaProfileValidationEnabledDefault, certificateWithRaProfileValidationEnabledCustom), timeNow);
        settingsCache.cacheSettings(SettingsSection.PLATFORM, settingService.getPlatformSettings());
    }


    @Test
    void testDoNotRevalidateFailed() {
        Mockito.doAnswer(execution -> {
            Certificate certificate = execution.getArgument(0);
            certificate.setStatusValidationTimestamp(OffsetDateTime.now());
            certificate.setValidationStatus(CertificateValidationStatus.FAILED);
            certificateRepository.save(certificate);
            return null;
        }).when(mockedCertificateService).validate(any());
        updateCertificateStatusTask.performJob(scheduledJobInfo, null);
        OffsetDateTime timeNow2 = OffsetDateTime.now();
        updateCertificateStatusTask.performJob(scheduledJobInfo, null);
        Assertions.assertTrue(certificateRepository.findAll().stream().allMatch(certificate -> certificate.getStatusValidationTimestamp() == null || certificate.getStatusValidationTimestamp().isBefore(timeNow2)));
    }

    @Test
    void testHandleExpiringCertificatesEvent() {
        // Certificate is expiring and is renewed by some certificate
        Certificate expiringRenewedCert = createCertificateForExpiringEventTest(CertificateValidationStatus.EXPIRING, null);
        // Certificate is expiring, but is not renewed by any certificate -> this is the only certificate that should be returned
        createCertificateForExpiringEventTest(CertificateValidationStatus.EXPIRING, expiringRenewedCert);
        // Not expiring and is renewed by some certificate
        Certificate renewedCert = createCertificateForExpiringEventTest(CertificateValidationStatus.VALID, null);
        // Not expiring and is not renewed by some certificate and is renewing previous cert
        createCertificateForExpiringEventTest(CertificateValidationStatus.VALID, renewedCert);
        // Expiring and is renewed by not yet issued certificate
        Certificate renewedByNotIssuedCert = createCertificateForExpiringEventTest(CertificateValidationStatus.EXPIRING, null);
        // certificate not issued renewing previous cert
        Certificate notIssued = createCertificateForExpiringEventTest(CertificateValidationStatus.VALID, renewedByNotIssuedCert);
        notIssued.setState(CertificateState.PENDING_ISSUE);
        certificateRepository.save(notIssued);


        ScheduledTaskResult result = updateCertificateStatusTask.performJob(null, null);

        Assertions.assertEquals(SchedulerJobExecutionStatus.SUCCESS, result.getStatus());
        Assertions.assertTrue(result.getResultMessage().contains("Handled 2 expiring "));
    }

    private Certificate createCertificateForExpiringEventTest(CertificateValidationStatus status, Certificate predecessorCertificate) {
        Certificate certificateEntity = new Certificate();
        CertificateContent content = new CertificateContent();
        content.setContent(String.valueOf(Math.random()));
        certificateContentRepository.save(content);
        certificateEntity.setCertificateContent(content);
        certificateEntity.setValidationStatus(status);
        certificateEntity.setState(CertificateState.ISSUED);
        certificateRepository.save(certificateEntity);
        if (predecessorCertificate != null) {
            CertificateRelation certificateRelation = new CertificateRelation();
            certificateRelation.setPredecessorCertificate(predecessorCertificate);
            certificateRelation.setSuccessorCertificate(certificateEntity);
            certificateRelation.setRelationType(CertificateRelationType.REPLACEMENT);
            certificateRelationRepository.save(certificateRelation);
        }
        return certificateEntity;
    }


    private void setCertificateContent(Certificate certificate) {
        CertificateContent certificateContent = new CertificateContent();
        certificateContentRepository.save(certificateContent);
        certificate.setCertificateContent(certificateContent);
    }

    private RaProfile getRaProfile(RaProfileCertificateValidationSettingsUpdateDto validationUpdateDto) {
        RaProfile raProfile = new RaProfile();
        raProfile.setEnabled(true);
        AuthorityInstanceReference authorityInstanceReference = new AuthorityInstanceReference();
        authorityInstanceReference.setStatus("connected");
        Connector connector = new Connector();
        connector.setVersion(ConnectorVersion.V1);
        connector.setStatus(ConnectorStatus.CONNECTED);
        connectorRepository.save(connector);
        authorityInstanceReference.setConnector(connector);
        authorityInstanceReferenceRepository.save(authorityInstanceReference);
        raProfile.setAuthorityInstanceReference(authorityInstanceReference);
        raProfile.setValidationFrequency(validationUpdateDto.getFrequency());
        raProfile.setValidationEnabled(validationUpdateDto.getEnabled());
        raProfileRepository.save(raProfile);
        return raProfile;
    }

    private void assertCorrectCertificatesHaveBeenValidated(List<Certificate> correctCertificates, OffsetDateTime timeNow) {
        List<Certificate> validatedCertificates = certificateRepository.findAll().stream()
                .filter(certificate -> certificate.getStatusValidationTimestamp() != null && certificate.getStatusValidationTimestamp().isAfter(timeNow))
                .toList();
        Assertions.assertEquals(correctCertificates.size(), validatedCertificates.size());
        Assertions.assertTrue(validatedCertificates.containsAll(correctCertificates));
    }

    @Test
    void testAcmeNonceCleanup() {
        // Create expired ACME nonces
        AcmeNonce expiredNonce1 = new AcmeNonce();
        expiredNonce1.setNonce("expired-nonce-1");
        expiredNonce1.setCreated(new Date(System.currentTimeMillis() - 3600000)); // 1 hour ago
        expiredNonce1.setExpires(new Date(System.currentTimeMillis() - 1800000)); // 30 minutes ago (expired)
        acmeNonceRepository.save(expiredNonce1);

        AcmeNonce expiredNonce2 = new AcmeNonce();
        expiredNonce2.setNonce("expired-nonce-2");
        expiredNonce2.setCreated(new Date(System.currentTimeMillis() - 7200000)); // 2 hours ago
        expiredNonce2.setExpires(new Date(System.currentTimeMillis() - 3600000)); // 1 hour ago (expired)
        acmeNonceRepository.save(expiredNonce2);

        // Create valid (not expired) ACME nonce
        AcmeNonce validNonce = new AcmeNonce();
        validNonce.setNonce("valid-nonce");
        validNonce.setCreated(new Date());
        validNonce.setExpires(new Date(System.currentTimeMillis() + 3600000)); // Expires in 1 hour
        acmeNonceRepository.save(validNonce);

        long initialCount = acmeNonceRepository.count();
        Assertions.assertEquals(3, initialCount);

        // Run the scheduled task
        updateCertificateStatusTask.performJob(scheduledJobInfo, null);

        // Verify expired nonces were deleted
        long finalCount = acmeNonceRepository.count();
        Assertions.assertEquals(1, finalCount);
        Assertions.assertTrue(acmeNonceRepository.findByNonce("valid-nonce").isPresent());
        Assertions.assertFalse(acmeNonceRepository.findByNonce("expired-nonce-1").isPresent());
        Assertions.assertFalse(acmeNonceRepository.findByNonce("expired-nonce-2").isPresent());
    }
}
