package com.otilm.core.signing.engine.certificate;

import com.otilm.api.model.client.signing.profile.workflow.SigningWorkflowType;
import com.otilm.api.model.common.enums.cryptography.KeyAlgorithm;
import com.otilm.api.model.core.certificate.CertificateState;
import com.otilm.core.model.crypto.CryptographicKeyItemModelFixtures;
import com.otilm.core.model.crypto.CryptographicKeyItemOperationModel;
import com.otilm.core.model.signing.CertificatePurposeRequirements;
import com.otilm.core.model.signing.SigningCertificateBuilder;
import com.otilm.core.model.signing.resolved.ResolvedStaticKeyManagedSigning;
import com.otilm.core.signing.engine.error.SigningEngineFailure;
import java.util.List;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

class StaticKeyManagedSigningCertificateValidatorTest {

    private final StaticKeyManagedSigningCertificateValidator provider = new StaticKeyManagedSigningCertificateValidator();

    private static final List<CryptographicKeyItemOperationModel> SIGNING_KEY_ITEMS = List
            .of(CryptographicKeyItemModelFixtures.activeSigningPrivateKey(KeyAlgorithm.RSA),
                    CryptographicKeyItemModelFixtures.publicKey(KeyAlgorithm.RSA));

    // ── validate() ───────────────────────────────────────────────────────────

    @Test
    void returnsNok_whenCertificateIsNotAcceptableForNonQualifiedTimestamping() {
        // given — a revoked certificate is not acceptable for signing
        var certificate = SigningCertificateBuilder.aSigningCertificate().state(CertificateState.REVOKED).build();
        var scheme = new ResolvedStaticKeyManagedSigning(certificate, SIGNING_KEY_ITEMS, null, List.of());

        // when
        var result = provider
                .validate(scheme, SigningWorkflowType.TIMESTAMPING, false, CertificatePurposeRequirements.NONE);

        // then
        assertThat(result).isInstanceOf(ValidationResult.Nok.class);
        assertThat(((ValidationResult.Nok) result).failure()).isEqualTo(SigningEngineFailure.MISCONFIGURED);
    }

    @Test
    void returnsOk_whenCertificateIsAcceptableForNonQualifiedTimestamping() {
        // given
        var scheme = new ResolvedStaticKeyManagedSigning(SigningCertificateBuilder.valid(), SIGNING_KEY_ITEMS, null,
                List.of());

        // when
        var result = provider
                .validate(scheme, SigningWorkflowType.TIMESTAMPING, false, CertificatePurposeRequirements.NONE);

        // then
        assertThat(result).isInstanceOf(ValidationResult.Ok.class);
    }

    @Test
    void returnsNok_whenCertificateHasNoQcComplianceForQualifiedTimestamping() {
        // given — qcCompliance is absent, which is required for qualified timestamps (ETSI EN 319 421)
        var scheme = new ResolvedStaticKeyManagedSigning(SigningCertificateBuilder.valid(), SIGNING_KEY_ITEMS, null,
                List.of());

        // when
        var result = provider
                .validate(scheme, SigningWorkflowType.TIMESTAMPING, true, CertificatePurposeRequirements.NONE);

        // then
        assertThat(result).isInstanceOf(ValidationResult.Nok.class);
        assertThat(((ValidationResult.Nok) result).failure()).isEqualTo(SigningEngineFailure.MISCONFIGURED);
    }

    @Test
    void returnsOk_whenCertificateIsAcceptableForQualifiedTimestamping() {
        // given
        var certificate = SigningCertificateBuilder.aSigningCertificate().qcCompliance(true).build();
        var scheme = new ResolvedStaticKeyManagedSigning(certificate, SIGNING_KEY_ITEMS, null, List.of());

        // when
        var result = provider
                .validate(scheme, SigningWorkflowType.TIMESTAMPING, true, CertificatePurposeRequirements.NONE);

        // then
        assertThat(result).isInstanceOf(ValidationResult.Ok.class);
    }

    @Test
    void appliesTheRfc3161RuleOnlyForTimestamping() {
        // given — a certificate whose EKU is not exclusive-critical timeStamping
        var scheme = aSchemeWithPlainDigitalSignatureCertificate();

        // when
        var timestamping = provider
                .validate(scheme, SigningWorkflowType.TIMESTAMPING, false, CertificatePurposeRequirements.NONE);
        var contentSigning = provider
                .validate(scheme, SigningWorkflowType.CONTENT_SIGNING, false, CertificatePurposeRequirements.NONE);

        // then
        assertThat(timestamping).isInstanceOf(ValidationResult.Nok.class);
        assertThat(((ValidationResult.Nok) timestamping).failure()).isEqualTo(SigningEngineFailure.MISCONFIGURED);
        assertThat(((ValidationResult.Nok) timestamping).logMessage())
                .isEqualTo("Signing certificate is not acceptable for non-qualified timestamping");
        assertThat(contentSigning).isInstanceOf(ValidationResult.Ok.class);
    }

    private static ResolvedStaticKeyManagedSigning aSchemeWithPlainDigitalSignatureCertificate() {
        var certificate = SigningCertificateBuilder
                .aSigningCertificate()
                .extendedKeyUsageOids(List.of())
                .extendedKeyUsageCritical(false)
                .build();
        return new ResolvedStaticKeyManagedSigning(certificate, SIGNING_KEY_ITEMS, null, List.of());
    }
}
