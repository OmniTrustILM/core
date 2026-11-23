package com.otilm.core.integration.repository;

import com.otilm.api.model.core.certificate.CertificateRelationType;
import com.otilm.api.model.core.certificate.CertificateState;
import com.otilm.api.model.core.certificate.CertificateValidationStatus;
import com.otilm.api.model.core.enums.CertificateProtocol;
import com.otilm.core.dao.entity.Certificate;
import com.otilm.core.dao.entity.RaProfile;
import com.otilm.core.dao.entity.RegistrationState;
import com.otilm.core.dao.entity.est.EstProfile;
import com.otilm.core.dao.repository.CertificateRegistrationAuthorizationRepository;
import com.otilm.core.dao.repository.CertificateRepository;
import com.otilm.core.dao.repository.EstReenrollmentSource;
import com.otilm.core.dao.repository.EstRequestedCertificate;
import com.otilm.core.dao.repository.X509CertificateRepository;
import com.otilm.core.model.auth.CertificateProtocolInfo;
import com.otilm.core.util.BaseSpringBootTest;
import com.otilm.core.util.CertificateUtil;
import com.otilm.core.util.seeders.CertificateRegistrationSeeder;
import com.otilm.core.util.seeders.EstRouteSeeder;
import java.nio.charset.StandardCharsets;
import java.security.NoSuchAlgorithmException;
import java.util.Date;
import java.util.Optional;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;
import org.springframework.beans.factory.annotation.Autowired;

import static com.otilm.core.util.builders.CertificateBuilder.aCertificate;
import static org.assertj.core.api.Assertions.assertThat;

class EstReenrollmentLookupITest extends BaseSpringBootTest {

    private static final byte[] REQUEST_BYTES = "the renewal request".getBytes(StandardCharsets.UTF_8);
    private static final byte[] OTHER_REQUEST_BYTES = "another request".getBytes(StandardCharsets.UTF_8);

    @Autowired
    private EstRouteSeeder estRouteSeeder;

    @Autowired
    private CertificateRegistrationSeeder registrations;

    @Autowired
    private CertificateRepository certificateRepository;

    @Autowired
    private X509CertificateRepository x509CertificateRepository;

    @Autowired
    private CertificateRegistrationAuthorizationRepository authorizationRepository;

    private RaProfile raProfile;
    private EstProfile estProfile;

    @BeforeEach
    void seedRoute() {
        raProfile = estRouteSeeder.seedRaProfile("devices-ra");
        estProfile = estRouteSeeder.seedEstProfile("est-devices", true, raProfile);
    }

    @Test
    void findsSource_whenFingerprintMatches() {
        // given
        var notBefore = new Date(1_700_000_000_000L);
        var notAfter = new Date(1_900_000_000_000L);
        Certificate source = certificateRepository
                .save(aCertificate()
                        .withFingerprint("source-fingerprint")
                        .withAltKeyFingerprint("source-alt-key-fingerprint")
                        .withSubjectDn("CN=device-1")
                        .withSubjectAlternativeNames("dNSName=device-1.example.com")
                        .withState(CertificateState.ISSUED)
                        .withValidationStatus(CertificateValidationStatus.VALID)
                        .withNotBefore(notBefore)
                        .withNotAfter(notAfter)
                        .withRaProfile(raProfile)
                        .build());
        estRouteSeeder.attributeToProtocol(source, CertificateProtocolInfo.est(estProfile.getUuid()));

        // when
        Optional<EstReenrollmentSource> found = x509CertificateRepository
                .findEstReenrollmentSource("source-fingerprint");

        // then
        assertThat(found).hasValueSatisfying(certificate -> {
            assertThat(certificate.getUuid()).isEqualTo(source.getUuid());
            assertThat(certificate.getState()).isEqualTo(CertificateState.ISSUED);
            assertThat(certificate.getArchived()).isFalse();
            assertThat(certificate.getNotBefore().getTime()).isEqualTo(notBefore.getTime());
            assertThat(certificate.getNotAfter().getTime()).isEqualTo(notAfter.getTime());
            assertThat(certificate.getValidationStatus()).isEqualTo(CertificateValidationStatus.VALID);
            assertThat(certificate.getRaProfileUuid()).isEqualTo(raProfile.getUuid());
            assertThat(certificate.getSubjectDn()).isEqualTo("CN=device-1");
            assertThat(certificate.getSubjectAlternativeNames()).isEqualTo("dNSName=device-1.example.com");
            assertThat(certificate.getAltKeyFingerprint()).isEqualTo("source-alt-key-fingerprint");
            assertThat(certificate.getProtocol()).isEqualTo(CertificateProtocol.EST);
            assertThat(certificate.getProtocolProfileUuid()).isEqualTo(estProfile.getUuid());
        });
    }

    @Test
    void findsNoSource_whenFingerprintIsUnknown() {
        // given
        certificateRepository.save(aCertificate().withFingerprint("source-fingerprint").build());

        // when
        Optional<EstReenrollmentSource> found = x509CertificateRepository
                .findEstReenrollmentSource("unknown-fingerprint");

        // then
        assertThat(found).isEmpty();
    }

    @Test
    void findsSuccessor_whenRenewalWasRequestedWithTheCsr() throws Exception {
        // given
        Certificate source = saveSource("source-fingerprint");
        Certificate successor = saveSuccessor(source, REQUEST_BYTES, CertificateState.PENDING_APPROVAL,
                CertificateRelationType.PENDING);
        var requestFingerprint = fingerprintOf(REQUEST_BYTES);

        // when
        Optional<EstRequestedCertificate> found = certificateRepository
                .findSuccessorRequestedWith(source.getUuid(), raProfile.getUuid(), requestFingerprint);

        // then
        assertThat(found).hasValueSatisfying(certificate -> {
            assertThat(certificate.getUuid()).isEqualTo(successor.getUuid());
            assertThat(certificate.getState()).isEqualTo(CertificateState.PENDING_APPROVAL);
            assertThat(certificate.getRequestFingerprint()).isEqualTo(requestFingerprint);
        });
    }

    @Test
    void findsIssuedSuccessor_whenRelationTypeHasChanged() throws Exception {
        // given
        Certificate source = saveSource("source-fingerprint");
        Certificate successor = saveSuccessor(source, REQUEST_BYTES, CertificateState.ISSUED,
                CertificateRelationType.RENEWAL);

        // when
        Optional<EstRequestedCertificate> found = certificateRepository
                .findSuccessorRequestedWith(source.getUuid(), raProfile.getUuid(), fingerprintOf(REQUEST_BYTES));

        // then
        assertThat(found).get().extracting(EstRequestedCertificate::getUuid).isEqualTo(successor.getUuid());
    }

    @Test
    void findsNoSuccessor_whenCsrDiffers() throws Exception {
        // given
        Certificate source = saveSource("source-fingerprint");
        saveSuccessor(source, REQUEST_BYTES, CertificateState.ISSUED, CertificateRelationType.REPLACEMENT);

        // when
        Optional<EstRequestedCertificate> found = certificateRepository
                .findSuccessorRequestedWith(source.getUuid(), raProfile.getUuid(), fingerprintOf(OTHER_REQUEST_BYTES));

        // then
        assertThat(found).isEmpty();
    }

    @Test
    void findsNoSuccessor_whenAnotherCertificateWasRenewed() throws Exception {
        // given
        Certificate source = saveSource("source-fingerprint");
        Certificate anotherSource = saveSource("another-fingerprint");
        saveSuccessor(anotherSource, REQUEST_BYTES, CertificateState.ISSUED, CertificateRelationType.REPLACEMENT);

        // when
        Optional<EstRequestedCertificate> found = certificateRepository
                .findSuccessorRequestedWith(source.getUuid(), raProfile.getUuid(), fingerprintOf(REQUEST_BYTES));

        // then
        assertThat(found).isEmpty();
    }

    @Test
    void findsNoSuccessor_whenSuccessorIsOnAnotherRaProfile() throws Exception {
        // given
        Certificate source = saveSource("source-fingerprint");
        RaProfile anotherRaProfile = estRouteSeeder.seedRaProfile("other-ra");
        estRouteSeeder
                .seedSuccessor(source, anotherRaProfile, REQUEST_BYTES, CertificateState.ISSUED,
                        CertificateRelationType.RENEWAL);

        // when
        Optional<EstRequestedCertificate> found = certificateRepository
                .findSuccessorRequestedWith(source.getUuid(), raProfile.getUuid(), fingerprintOf(REQUEST_BYTES));

        // then
        assertThat(found).isEmpty();
    }

    @ParameterizedTest
    @EnumSource(value = CertificateState.class, names = {"REQUESTED", "PENDING_APPROVAL", "PENDING_ISSUE"})
    void findsPendingSuccessor_whenSuccessorWaits(CertificateState waiting) {
        // given
        Certificate source = saveSource("source-fingerprint");
        saveSuccessor(source, REQUEST_BYTES, waiting, CertificateRelationType.PENDING);

        // when
        boolean pending = certificateRepository.existsPendingSuccessor(source.getUuid());

        // then
        assertThat(pending).isTrue();
    }

    @Test
    void findsNoPendingSuccessor_whenOnlyAnotherSourceHasOne() {
        // given
        Certificate source = saveSource("source-fingerprint");
        Certificate anotherSource = saveSource("another-fingerprint");
        saveSuccessor(anotherSource, REQUEST_BYTES, CertificateState.PENDING_APPROVAL, CertificateRelationType.PENDING);

        // when
        boolean pending = certificateRepository.existsPendingSuccessor(source.getUuid());

        // then
        assertThat(pending).isFalse();
    }

    @Test
    void findsNoPendingSuccessor_whenSuccessorIsIssued() {
        // given
        Certificate source = saveSource("source-fingerprint");
        saveSuccessor(source, REQUEST_BYTES, CertificateState.ISSUED, CertificateRelationType.REPLACEMENT);

        // when
        boolean pending = certificateRepository.existsPendingSuccessor(source.getUuid());

        // then
        assertThat(pending).isFalse();
    }

    @ParameterizedTest
    @EnumSource(value = RegistrationState.class, names = "CLOSED", mode = EnumSource.Mode.EXCLUDE)
    void findsOpenAuthorization_whenNotClosed(RegistrationState state) {
        // given
        Certificate registered = registrations.seedRegistrationWithAuthorization(raProfile, "CN=device-1", state);

        // when
        boolean open = authorizationRepository
                .existsByCertificateUuidAndStateNot(registered.getUuid(), RegistrationState.CLOSED);

        // then
        assertThat(open).isTrue();
    }

    @Test
    void findsNoOpenAuthorization_whenClosed() {
        // given
        Certificate registered = registrations
                .seedRegistrationWithAuthorization(raProfile, "CN=device-1", RegistrationState.CLOSED);

        // when
        boolean open = authorizationRepository
                .existsByCertificateUuidAndStateNot(registered.getUuid(), RegistrationState.CLOSED);

        // then
        assertThat(open).isFalse();
    }

    // ── Helpers ───────────────────────────────────────────────────────────────

    private Certificate saveSource(String fingerprint) {
        return certificateRepository
                .save(aCertificate()
                        .withFingerprint(fingerprint)
                        .withState(CertificateState.ISSUED)
                        .withRaProfile(raProfile)
                        .build());
    }

    private Certificate saveSuccessor(Certificate source, byte[] requestBytes, CertificateState state,
            CertificateRelationType relationType) {
        return estRouteSeeder.seedSuccessor(source, raProfile, requestBytes, state, relationType);
    }

    private static String fingerprintOf(byte[] requestBytes) throws NoSuchAlgorithmException {
        return CertificateUtil.getThumbprint(requestBytes);
    }
}
