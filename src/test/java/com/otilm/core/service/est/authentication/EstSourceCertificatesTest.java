package com.otilm.core.service.est.authentication;

import com.otilm.api.model.core.certificate.CertificateState;
import com.otilm.api.model.core.certificate.CertificateValidationStatus;
import com.otilm.api.model.core.enums.CertificateProtocol;
import com.otilm.core.dao.entity.RaProfile;
import com.otilm.core.dao.entity.est.EstProfile;
import com.otilm.core.dao.repository.EstReenrollmentSource;
import com.otilm.core.dao.repository.X509CertificateRepository;
import com.otilm.core.service.est.EstRoute;
import com.otilm.core.service.est.message.EstError;
import com.otilm.core.service.est.message.EstException;
import com.otilm.core.util.CryptographyUtil;
import com.otilm.core.util.PkiFixtures;
import com.otilm.core.util.PkiFixtures.Ca;
import java.security.PublicKey;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.time.Instant;
import java.util.Date;
import java.util.Optional;
import java.util.UUID;
import org.assertj.core.api.ThrowableAssert.ThrowingCallable;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import static com.otilm.core.util.EstClientCredentialsFixtures.certificateCredentials;
import static com.otilm.core.util.EstClientCredentialsFixtures.malformedCertificateCredentials;
import static com.otilm.core.util.EstClientCredentialsFixtures.noCredentials;
import static com.otilm.core.util.builders.EstProfileBuilder.anEstProfile;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.lenient;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class EstSourceCertificatesTest {

    private static final String REALM = "devices";

    @Mock
    private X509CertificateRepository repository;

    private EstSourceCertificates sourceCertificates;
    private EstRoute route;
    private RaProfile raProfile;
    private EstProfile estProfile;
    private X509Certificate clientCertificate;
    private String fingerprint;

    @BeforeEach
    void createRouteAndClientCertificate() {
        sourceCertificates = new EstSourceCertificates(repository);
        raProfile = new RaProfile();
        raProfile.setUuid(UUID.randomUUID());
        estProfile = anEstProfile().withUuid(UUID.randomUUID()).build();
        route = new EstRoute(estProfile, raProfile, false, REALM);
        Ca ca = PkiFixtures.rootCa("EST test CA");
        clientCertificate = PkiFixtures.clientCertificate(ca);
        fingerprint = certificateCredentials(clientCertificate).certificate().orElseThrow().thumbprint();
    }

    @Test
    void returnsSource_whenIssuedThroughTheRoute() throws Exception {
        // given
        EstReenrollmentSource stored = buildStoredSource();
        var notBefore = new Date(System.currentTimeMillis() - 1_000_000);
        var notAfter = new Date(System.currentTimeMillis() + 1_000_000);
        lenient().when(stored.getNotBefore()).thenReturn(notBefore);
        lenient().when(stored.getNotAfter()).thenReturn(notAfter);
        when(repository.findEstReenrollmentSource(fingerprint)).thenReturn(Optional.of(stored));

        // when
        EstSourceCertificate source = sourceCertificates.authenticate(route, certificateCredentials(clientCertificate));

        // then
        PublicKey presentedKey = CryptographyUtil.decodePublicKey(clientCertificate.getPublicKey().getEncoded());
        assertThat(source)
                .isEqualTo(new EstSourceCertificate(stored.getUuid(), fingerprint, presentedKey, "CN=device-1",
                        "dNSName=device-1.example.com", notBefore, notAfter));
    }

    @Test
    void refusesSource_whenNoCertificateIsForwarded() {
        // given
        var credentials = noCredentials();

        // when
        ThrowingCallable authenticate = () -> sourceCertificates.authenticate(route, credentials);

        // then
        assertRejected(authenticate);
    }

    @Test
    void refusesSource_whenHeaderIsMalformed() {
        // given
        var credentials = malformedCertificateCredentials();

        // when
        ThrowingCallable authenticate = () -> sourceCertificates.authenticate(route, credentials);

        // then
        assertRejected(authenticate);
    }

    @Test
    void refusesSource_whenCertificateIsUnknown() {
        // given
        when(repository.findEstReenrollmentSource(fingerprint)).thenReturn(Optional.empty());

        // when
        ThrowingCallable authenticate = () -> sourceCertificates
                .authenticate(route, certificateCredentials(clientCertificate));

        // then
        assertRejected(authenticate);
    }

    @ParameterizedTest
    @EnumSource(value = CertificateState.class, names = "ISSUED", mode = EnumSource.Mode.EXCLUDE)
    void refusesSource_whenCertificateIsNotIssued(CertificateState state) {
        // given
        EstReenrollmentSource stored = buildStoredSource();
        lenient().when(stored.getState()).thenReturn(state);

        // when
        ThrowingCallable authenticate = authenticating(stored);

        // then
        assertRejected(authenticate);
    }

    @Test
    void refusesSource_whenCertificateIsArchived() {
        // given
        EstReenrollmentSource stored = buildStoredSource();
        lenient().when(stored.getArchived()).thenReturn(true);

        // when
        ThrowingCallable authenticate = authenticating(stored);

        // then
        assertRejected(authenticate);
    }

    @Test
    void refusesSource_whenCertificateIsNotYetValid() {
        // given
        EstReenrollmentSource stored = buildStoredSource();
        lenient().when(stored.getNotBefore()).thenReturn(Date.from(Instant.now().plus(Duration.ofHours(1))));

        // when
        ThrowingCallable authenticate = authenticating(stored);

        // then
        assertRejected(authenticate);
    }

    @Test
    void refusesSource_whenCertificateHasExpired() {
        // given
        EstReenrollmentSource stored = buildStoredSource();
        lenient().when(stored.getNotAfter()).thenReturn(Date.from(Instant.now().minus(Duration.ofHours(1))));

        // when
        ThrowingCallable authenticate = authenticating(stored);

        // then
        assertRejected(authenticate);
    }

    @ParameterizedTest
    @EnumSource(value = CertificateValidationStatus.class, names = {"REVOKED", "EXPIRED", "INVALID"})
    void refusesSource_whenValidationStatusForbidsRenewal(CertificateValidationStatus status) {
        // given
        EstReenrollmentSource stored = buildStoredSource();
        lenient().when(stored.getValidationStatus()).thenReturn(status);

        // when
        ThrowingCallable authenticate = authenticating(stored);

        // then
        assertRejected(authenticate);
    }

    @Test
    void refusesSource_whenCertificateBelongsToAnotherRaProfile() {
        // given
        EstReenrollmentSource stored = buildStoredSource();
        lenient().when(stored.getRaProfileUuid()).thenReturn(UUID.randomUUID());

        // when
        ThrowingCallable authenticate = authenticating(stored);

        // then
        assertRejected(authenticate);
    }

    @ParameterizedTest
    @EnumSource(value = CertificateProtocol.class, names = "EST", mode = EnumSource.Mode.EXCLUDE)
    void refusesSource_whenCertificateWasNotRequestedThroughEst(CertificateProtocol protocol) {
        // given
        EstReenrollmentSource stored = buildStoredSource();
        lenient().when(stored.getProtocol()).thenReturn(protocol);

        // when
        ThrowingCallable authenticate = authenticating(stored);

        // then
        assertRejected(authenticate);
    }

    @Test
    void refusesSource_whenCertificateHasNoProtocolAssociation() {
        // given
        EstReenrollmentSource stored = buildStoredSource();
        lenient().when(stored.getProtocol()).thenReturn(null);
        lenient().when(stored.getProtocolProfileUuid()).thenReturn(null);

        // when
        ThrowingCallable authenticate = authenticating(stored);

        // then
        assertRejected(authenticate);
    }

    @ParameterizedTest
    @EnumSource(value = CertificateValidationStatus.class, names = {"REVOKED", "EXPIRED", "INVALID"},
            mode = EnumSource.Mode.EXCLUDE)
    void returnsSource_whenValidationStatusAllowsRenewal(CertificateValidationStatus status) {
        // given
        EstReenrollmentSource stored = buildStoredSource();
        lenient().when(stored.getValidationStatus()).thenReturn(status);
        when(repository.findEstReenrollmentSource(fingerprint)).thenReturn(Optional.of(stored));

        // when
        EstSourceCertificate source = sourceCertificates.authenticate(route, certificateCredentials(clientCertificate));

        // then
        assertThat(source.uuid()).isEqualTo(stored.getUuid());
    }

    @Test
    void returnsSource_whenValidationStatusIsUnknown() {
        // given
        EstReenrollmentSource stored = buildStoredSource();
        lenient().when(stored.getValidationStatus()).thenReturn(null);
        when(repository.findEstReenrollmentSource(fingerprint)).thenReturn(Optional.of(stored));

        // when
        EstSourceCertificate source = sourceCertificates.authenticate(route, certificateCredentials(clientCertificate));

        // then
        assertThat(source.uuid()).isEqualTo(stored.getUuid());
    }

    @Test
    void refusesSource_whenCertificateWasRequestedThroughAnotherEstProfile() {
        // given
        EstReenrollmentSource stored = buildStoredSource();
        lenient().when(stored.getProtocolProfileUuid()).thenReturn(UUID.randomUUID());

        // when
        ThrowingCallable authenticate = authenticating(stored);

        // then
        assertRejected(authenticate);
    }

    @Test
    void refusesSource_whenCertificateHasAnAlternativeKey() {
        // given
        EstReenrollmentSource stored = buildStoredSource();
        lenient().when(stored.getAltKeyFingerprint()).thenReturn("alternative-key-fingerprint");

        // when
        ThrowingCallable authenticate = authenticating(stored);

        // then
        assertRejected(authenticate);
    }

    // ── Helpers ───────────────────────────────────────────────────────────────

    /** A stored certificate that the route accepts; a test overrides the one answer that it refuses. */
    private EstReenrollmentSource buildStoredSource() {
        EstReenrollmentSource stored = mock(EstReenrollmentSource.class);
        lenient().when(stored.getUuid()).thenReturn(UUID.randomUUID());
        lenient().when(stored.getState()).thenReturn(CertificateState.ISSUED);
        lenient().when(stored.getArchived()).thenReturn(false);
        lenient().when(stored.getNotBefore()).thenReturn(Date.from(Instant.now().minus(Duration.ofDays(1))));
        lenient().when(stored.getNotAfter()).thenReturn(Date.from(Instant.now().plus(Duration.ofDays(1))));
        lenient().when(stored.getValidationStatus()).thenReturn(CertificateValidationStatus.VALID);
        lenient().when(stored.getRaProfileUuid()).thenReturn(raProfile.getUuid());
        lenient().when(stored.getSubjectDn()).thenReturn("CN=device-1");
        lenient().when(stored.getSubjectAlternativeNames()).thenReturn("dNSName=device-1.example.com");
        lenient().when(stored.getAltKeyFingerprint()).thenReturn(null);
        lenient().when(stored.getProtocol()).thenReturn(CertificateProtocol.EST);
        lenient().when(stored.getProtocolProfileUuid()).thenReturn(estProfile.getUuid());
        return stored;
    }

    private ThrowingCallable authenticating(EstReenrollmentSource stored) {
        when(repository.findEstReenrollmentSource(fingerprint)).thenReturn(Optional.of(stored));
        return () -> sourceCertificates.authenticate(route, certificateCredentials(clientCertificate));
    }

    private static void assertRejected(ThrowingCallable authenticate) {
        assertThatThrownBy(authenticate).isInstanceOfSatisfying(EstException.class, e -> {
            assertThat(e.error()).isEqualTo(EstError.CERTIFICATE_REJECTED);
            assertThat(e.realm()).contains(REALM);
        });
    }
}
