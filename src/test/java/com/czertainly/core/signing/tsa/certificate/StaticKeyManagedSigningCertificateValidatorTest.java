package com.czertainly.core.signing.tsa.certificate;

import com.czertainly.api.interfaces.core.tsp.error.TspFailureInfo;
import com.czertainly.api.model.common.enums.cryptography.KeyAlgorithm;
import com.czertainly.api.model.core.certificate.CertificateState;
import com.czertainly.core.model.crypto.CryptographicKeyItemModel;
import com.czertainly.core.model.crypto.CryptographicKeyItemModelFixtures;
import com.czertainly.core.model.signing.SigningCertificateBuilder;
import com.czertainly.core.model.signing.resolved.ResolvedStaticKeyManagedSigning;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

class StaticKeyManagedSigningCertificateValidatorTest {

    private final StaticKeyManagedSigningCertificateValidator provider = new StaticKeyManagedSigningCertificateValidator();

    private static final List<CryptographicKeyItemModel> SIGNING_KEY_ITEMS = List.of(
            CryptographicKeyItemModelFixtures.activeSigningPrivateKey(KeyAlgorithm.RSA),
            CryptographicKeyItemModelFixtures.publicKey(KeyAlgorithm.RSA));

    // ── validate() ───────────────────────────────────────────────────────────

    @Test
    void validate_returnsNok_whenCertificateIsNotAcceptableForNonQualifiedTimestamping() {
        // given — a revoked certificate is not acceptable for signing
        var certificate = SigningCertificateBuilder.aSigningCertificate().state(CertificateState.REVOKED).build();
        var scheme = new ResolvedStaticKeyManagedSigning(certificate, SIGNING_KEY_ITEMS, null, List.of());

        // when
        var result = provider.validate(scheme, false);

        // then
        assertThat(result).isInstanceOf(ValidationResult.Nok.class);
        assertThat(((ValidationResult.Nok) result).failureInfo()).isEqualTo(TspFailureInfo.SYSTEM_FAILURE);
    }

    @Test
    void validate_returnsOk_whenCertificateIsAcceptableForNonQualifiedTimestamping() {
        // given
        var scheme = new ResolvedStaticKeyManagedSigning(SigningCertificateBuilder.valid(), SIGNING_KEY_ITEMS, null, List.of());

        // when
        var result = provider.validate(scheme, false);

        // then
        assertThat(result).isInstanceOf(ValidationResult.Ok.class);
    }

    @Test
    void validate_returnsNok_whenCertificateHasNoQcComplianceForQualifiedTimestamping() {
        // given — qcCompliance is absent, which is required for qualified timestamps (ETSI EN 319 421)
        var scheme = new ResolvedStaticKeyManagedSigning(SigningCertificateBuilder.valid(), SIGNING_KEY_ITEMS, null, List.of());

        // when
        var result = provider.validate(scheme, true);

        // then
        assertThat(result).isInstanceOf(ValidationResult.Nok.class);
        assertThat(((ValidationResult.Nok) result).failureInfo()).isEqualTo(TspFailureInfo.SYSTEM_FAILURE);
    }

    @Test
    void validate_returnsOk_whenCertificateIsAcceptableForQualifiedTimestamping() {
        // given
        var certificate = SigningCertificateBuilder.aSigningCertificate().qcCompliance(true).build();
        var scheme = new ResolvedStaticKeyManagedSigning(certificate, SIGNING_KEY_ITEMS, null, List.of());

        // when
        var result = provider.validate(scheme, true);

        // then
        assertThat(result).isInstanceOf(ValidationResult.Ok.class);
    }
}
