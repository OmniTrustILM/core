package com.otilm.core.integration.repository;

import com.otilm.api.model.core.certificate.CertificateState;
import com.otilm.api.model.core.enums.CertificateProtocol;
import com.otilm.core.dao.entity.Certificate;
import com.otilm.core.dao.entity.CertificateProtocolAssociation;
import com.otilm.core.dao.entity.RaProfile;
import com.otilm.core.dao.entity.est.EstProfile;
import com.otilm.core.dao.repository.CertificateContentRepository;
import com.otilm.core.dao.repository.CertificateProtocolAssociationRepository;
import com.otilm.core.dao.repository.CertificateRepository;
import com.otilm.core.dao.repository.CertificateRequestRepository;
import com.otilm.core.dao.repository.EstRequestedCertificate;
import com.otilm.core.util.BaseSpringBootTest;
import com.otilm.core.util.CertificateUtil;
import com.otilm.core.util.seeders.EstRouteSeeder;
import java.nio.charset.StandardCharsets;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;
import java.util.Date;
import java.util.Optional;
import java.util.UUID;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;
import org.springframework.beans.factory.annotation.Autowired;

import static com.otilm.core.util.builders.CertificateBuilder.aCertificate;
import static com.otilm.core.util.builders.CertificateContentBuilder.aCertificateContent;
import static com.otilm.core.util.builders.CertificateRequestEntityBuilder.aCertificateRequest;
import static org.assertj.core.api.Assertions.assertThat;

class EstRequestedCertificateLookupITest extends BaseSpringBootTest {

    private static final byte[] REQUEST_BYTES = "the first request".getBytes(StandardCharsets.UTF_8);
    private static final byte[] OTHER_REQUEST_BYTES = "another request".getBytes(StandardCharsets.UTF_8);

    @Autowired
    private EstRouteSeeder estRouteSeeder;

    @Autowired
    private CertificateRepository certificateRepository;

    @Autowired
    private CertificateRequestRepository certificateRequestRepository;

    @Autowired
    private CertificateProtocolAssociationRepository certificateProtocolAssociationRepository;

    @Autowired
    private CertificateContentRepository certificateContentRepository;

    private RaProfile raProfile;
    private EstProfile estProfile;

    @BeforeEach
    void seedRoute() {
        raProfile = estRouteSeeder.seedRaProfile("devices-ra");
        estProfile = estRouteSeeder.seedEstProfile("est-devices", true, raProfile);
    }

    @Test
    void findsCertificate_whenRequestWasMadeThroughTheRoute() throws Exception {
        // given
        var notAfter = new Date(1_900_000_000_000L);
        var requestFingerprint = fingerprintOf(REQUEST_BYTES);
        Certificate requested = saveRequestedCertificate(raProfile, CertificateProtocol.EST, estProfile.getUuid(),
                REQUEST_BYTES, CertificateState.ISSUED, notAfter);

        // when
        Optional<EstRequestedCertificate> found = certificateRepository
                .findLatestRequestedThroughEst(raProfile.getUuid(), estProfile.getUuid(), requestFingerprint);

        // then
        assertThat(found).hasValueSatisfying(certificate -> {
            assertThat(certificate.getUuid()).isEqualTo(requested.getUuid());
            assertThat(certificate.getState()).isEqualTo(CertificateState.ISSUED);
            assertThat(certificate.getNotAfter().getTime()).isEqualTo(notAfter.getTime());
            assertThat(certificate.getRequestFingerprint()).isEqualTo(requestFingerprint);
        });
    }

    @Test
    void findsNewestCertificate_whenTheSameCsrWasRequestedTwice() throws Exception {
        // given
        saveRequestedCertificate(raProfile, CertificateProtocol.EST, estProfile.getUuid(), REQUEST_BYTES,
                CertificateState.REJECTED, null);
        Certificate newest = saveRequestedCertificate(raProfile, CertificateProtocol.EST, estProfile.getUuid(),
                REQUEST_BYTES, CertificateState.ISSUED, null);

        // when
        Optional<EstRequestedCertificate> found = certificateRepository
                .findLatestRequestedThroughEst(raProfile.getUuid(), estProfile.getUuid(), fingerprintOf(REQUEST_BYTES));

        // then
        assertThat(found).get().extracting(EstRequestedCertificate::getUuid).isEqualTo(newest.getUuid());
    }

    @Test
    void findsNothing_whenFingerprintDiffers() throws Exception {
        // given
        saveRequestedCertificate(raProfile, CertificateProtocol.EST, estProfile.getUuid(), REQUEST_BYTES,
                CertificateState.ISSUED, null);
        var otherFingerprint = fingerprintOf(OTHER_REQUEST_BYTES);

        // when
        Optional<EstRequestedCertificate> found = certificateRepository
                .findLatestRequestedThroughEst(raProfile.getUuid(), estProfile.getUuid(), otherFingerprint);

        // then
        assertThat(found).isEmpty();
    }

    @Test
    void findsNothing_whenRaProfileDiffers() throws Exception {
        // given
        saveRequestedCertificate(raProfile, CertificateProtocol.EST, estProfile.getUuid(), REQUEST_BYTES,
                CertificateState.ISSUED, null);
        RaProfile otherRaProfile = estRouteSeeder.seedRaProfile("other-ra");

        // when
        Optional<EstRequestedCertificate> found = certificateRepository
                .findLatestRequestedThroughEst(otherRaProfile.getUuid(), estProfile.getUuid(),
                        fingerprintOf(REQUEST_BYTES));

        // then
        assertThat(found).isEmpty();
    }

    @ParameterizedTest
    @EnumSource(value = CertificateProtocol.class, names = "EST", mode = EnumSource.Mode.EXCLUDE)
    void findsNothing_whenCertificateWasRequestedThroughAnotherProtocol(CertificateProtocol anotherProtocol)
            throws Exception {
        // given
        saveRequestedCertificate(raProfile, anotherProtocol, estProfile.getUuid(), REQUEST_BYTES,
                CertificateState.ISSUED, null);

        // when
        Optional<EstRequestedCertificate> found = certificateRepository
                .findLatestRequestedThroughEst(raProfile.getUuid(), estProfile.getUuid(), fingerprintOf(REQUEST_BYTES));

        // then
        assertThat(found).isEmpty();
    }

    @Test
    void findsNothing_whenCertificateWasRequestedThroughAnotherEstProfile() throws Exception {
        // given
        EstProfile otherEstProfile = estRouteSeeder.seedEstProfile("est-other", true, raProfile);
        saveRequestedCertificate(raProfile, CertificateProtocol.EST, otherEstProfile.getUuid(), REQUEST_BYTES,
                CertificateState.ISSUED, null);

        // when
        Optional<EstRequestedCertificate> found = certificateRepository
                .findLatestRequestedThroughEst(raProfile.getUuid(), estProfile.getUuid(), fingerprintOf(REQUEST_BYTES));

        // then
        assertThat(found).isEmpty();
    }

    @Test
    void findsNothing_whenCertificateIsArchived() throws Exception {
        // given
        Certificate archived = saveRequestedCertificate(raProfile, CertificateProtocol.EST, estProfile.getUuid(),
                REQUEST_BYTES, CertificateState.ISSUED, null);
        archived.setArchived(true);
        certificateRepository.save(archived);

        // when
        Optional<EstRequestedCertificate> found = certificateRepository
                .findLatestRequestedThroughEst(raProfile.getUuid(), estProfile.getUuid(), fingerprintOf(REQUEST_BYTES));

        // then
        assertThat(found).isEmpty();
    }

    @Test
    void readsStateAndRequestFingerprint_whenLookedUpByUuid() throws Exception {
        // given
        Certificate requested = saveRequestedCertificate(raProfile, CertificateProtocol.EST, estProfile.getUuid(),
                REQUEST_BYTES, CertificateState.PENDING_APPROVAL, null);
        var requestFingerprint = fingerprintOf(REQUEST_BYTES);

        // when
        Optional<EstRequestedCertificate> found = certificateRepository
                .findEstRequestedCertificateByUuid(requested.getUuid());

        // then
        assertThat(found).hasValueSatisfying(certificate -> {
            assertThat(certificate.getState()).isEqualTo(CertificateState.PENDING_APPROVAL);
            assertThat(certificate.getRequestFingerprint()).isEqualTo(requestFingerprint);
        });
    }

    @Test
    void readsContent_whenCertificateCarriesTheRequest() throws Exception {
        // given
        Certificate issued = saveRequestedCertificate(raProfile, CertificateProtocol.EST, estProfile.getUuid(),
                REQUEST_BYTES, CertificateState.ISSUED, null);
        var content = "the content of the issued certificate";
        attachContent(issued, content);

        // when
        Optional<String> found = certificateRepository
                .findContentByUuidAndRequestFingerprint(issued.getUuid(), fingerprintOf(REQUEST_BYTES));

        // then
        assertThat(found).contains(content);
    }

    @Test
    void readsNoContent_whenCertificateCarriesAnotherRequest() throws Exception {
        // given
        Certificate issued = saveRequestedCertificate(raProfile, CertificateProtocol.EST, estProfile.getUuid(),
                REQUEST_BYTES, CertificateState.ISSUED, null);
        attachContent(issued, "the content of the issued certificate");
        var otherFingerprint = fingerprintOf(OTHER_REQUEST_BYTES);

        // when
        Optional<String> found = certificateRepository
                .findContentByUuidAndRequestFingerprint(issued.getUuid(), otherFingerprint);

        // then
        assertThat(found).isEmpty();
    }

    @Test
    void readsNoRequestFingerprint_whenRegistrationHasNoRequest() {
        // given
        Certificate registered = certificateRepository
                .save(aCertificate().withRaProfile(raProfile).withState(CertificateState.REGISTERED).build());

        // when
        Optional<EstRequestedCertificate> found = certificateRepository
                .findEstRequestedCertificateByUuid(registered.getUuid());

        // then
        assertThat(found).hasValueSatisfying(certificate -> {
            assertThat(certificate.getState()).isEqualTo(CertificateState.REGISTERED);
            assertThat(certificate.getRequestFingerprint()).isNull();
        });
    }

    // ── Helpers ───────────────────────────────────────────────────────────────

    private Certificate saveRequestedCertificate(RaProfile certificateRaProfile, CertificateProtocol protocol,
            UUID protocolProfileUuid, byte[] requestBytes, CertificateState state, Date notAfter) {
        var request = certificateRequestRepository
                .save(aCertificateRequest().withContent(Base64.getEncoder().encodeToString(requestBytes)).build());
        Certificate certificate = certificateRepository
                .save(aCertificate()
                        .withRaProfile(certificateRaProfile)
                        .withState(state)
                        .withNotAfter(notAfter)
                        .withCertificateRequestUuid(request.getUuid())
                        .build());
        var association = new CertificateProtocolAssociation();
        association.setCertificateUuid(certificate.getUuid());
        association.setProtocol(protocol);
        association.setProtocolProfileUuid(protocolProfileUuid);
        certificateProtocolAssociationRepository.save(association);
        return certificate;
    }

    private void attachContent(Certificate certificate, String content) {
        certificate
                .setCertificateContent(
                        certificateContentRepository.save(aCertificateContent().withContent(content).build()));
        certificateRepository.save(certificate);
    }

    private static String fingerprintOf(byte[] requestBytes) throws NoSuchAlgorithmException {
        return CertificateUtil.getThumbprint(requestBytes);
    }
}
