package com.otilm.core.integration.service.signingprofile;

import com.otilm.api.exception.ValidationException;
import com.otilm.api.model.client.signing.profile.SigningProfileRequestDto;
import com.otilm.api.model.common.enums.cryptography.KeyAlgorithm;
import com.otilm.api.model.common.signature.SignatureFamily;
import com.otilm.api.model.common.signature.SignatureLevel;
import com.otilm.api.model.core.certificate.CertificateKeyUsage;
import com.otilm.api.model.core.certificate.CertificateState;
import com.otilm.api.model.core.certificate.CertificateValidationStatus;
import com.otilm.core.dao.entity.Certificate;
import com.otilm.core.dao.entity.CryptographicKey;
import com.otilm.core.dao.entity.X509CertificateEntity;
import com.otilm.core.service.signingprofile.SigningProfileTestBase;
import com.otilm.core.util.CertificateTestUtil;
import com.otilm.core.util.seeders.CryptographicKeySeeder.KeyItemSpec;
import java.util.UUID;
import java.util.stream.Stream;
import org.assertj.core.api.ThrowableAssert.ThrowingCallable;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import static com.otilm.core.util.builders.CertificateBuilder.aCertificate;
import static com.otilm.core.util.builders.ContentSigningWorkflowRequestDtoBuilder.aContentSigningWorkflow;
import static com.otilm.core.util.builders.SigningProfileRequestDtoBuilder.aSigningProfileRequest;
import static com.otilm.core.util.seeders.CryptographicKeySeeder.KeyItemSpec.signingPrivateKey;
import static com.otilm.core.util.seeders.CryptographicKeySeeder.KeyItemSpec.verifyingPublicKey;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.junit.jupiter.api.Named.named;

class ContentSigningSignerKeyITest extends SigningProfileTestBase {

    @Test
    void refusesTheSigner_whenItHasNoKey() throws Exception {
        // given
        CryptographicKey noKey = null;
        X509CertificateEntity signer = seedSigner(noKey);
        SigningProfileRequestDto request = managedPadesSigningRequest(signer.getUuid());

        // when
        ThrowingCallable create = () -> signingProfileService.createSigningProfile(request);

        // then
        assertThatThrownBy(create)
                .isInstanceOf(ValidationException.class)
                .hasMessageContaining("is not eligible for signing workflow type")
                .hasMessageContaining("No cryptographic key associated with certificate");
    }

    @Test
    void refusesTheSigner_whenNoTokenHoldsItsKey() throws Exception {
        // given
        CryptographicKey keyOutsideAnyToken = cryptographicKeySeeder
                .seedKey("uploaded-key", null, null, signingPrivateKey(KeyAlgorithm.RSA),
                        verifyingPublicKey(KeyAlgorithm.RSA));
        X509CertificateEntity signer = seedSigner(keyOutsideAnyToken);
        SigningProfileRequestDto request = managedPadesSigningRequest(signer.getUuid());

        // when
        ThrowingCallable create = () -> signingProfileService.createSigningProfile(request);

        // then
        assertThatThrownBy(create)
                .isInstanceOf(ValidationException.class)
                .hasMessageContaining("is not eligible for signing workflow type")
                .hasMessageContaining("referenced by signing certificate " + signer.getUuid() + " not found");
    }

    @ParameterizedTest
    @MethodSource("keysHoldingOneHalf")
    void refusesTheSigner_whenItsKeyLacksAHalf(KeyItemSpec onlyHalf, String missingHalf) throws Exception {
        // given
        CryptographicKey halfKey = cryptographicKeySeeder
                .seedKey("half-key", tokenProfile, tokenProfile.getTokenInstanceReference(), onlyHalf);
        X509CertificateEntity signer = seedSigner(halfKey);
        SigningProfileRequestDto request = managedPadesSigningRequest(signer.getUuid());

        // when
        ThrowingCallable create = () -> signingProfileService.createSigningProfile(request);

        // then
        assertThatThrownBy(create)
                .isInstanceOf(ValidationException.class)
                .hasMessageContaining("is not eligible for signing workflow type")
                .hasMessageContaining("No " + missingHalf + " key item found");
    }

    // ── Helpers ───────────────────────────────────────────────────────────────

    static Stream<Arguments> keysHoldingOneHalf() {
        return Stream
                .of(Arguments.of(named("only a public key", verifyingPublicKey(KeyAlgorithm.RSA)), "private"),
                        Arguments.of(named("only a private key", signingPrivateKey(KeyAlgorithm.RSA)), "public"));
    }

    private X509CertificateEntity seedSigner(CryptographicKey key) throws Exception {
        X509CertificateEntity signer = aCertificate()
                .withKey(key)
                .withState(CertificateState.ISSUED)
                .withValidationStatus(CertificateValidationStatus.VALID)
                .withKeyUsage(CertificateKeyUsage.DIGITAL_SIGNATURE)
                .build();
        Certificate content = certificateService
                .createCertificateEntity(CertificateTestUtil.createEndEntityCertificate());
        signer.setCertificateContent(content.getCertificateContent());
        signer.setCertificateContentId(content.getCertificateContentId());
        return certificateRepository.saveAndFlush(signer);
    }

    private SigningProfileRequestDto managedPadesSigningRequest(UUID certificateUuid) {
        return aSigningProfileRequest()
                .withName("managed-pades")
                .withStaticKeyManagedSigning(certificateUuid)
                .withContentSigning(aContentSigningWorkflow()
                        .withSignatureFormattingConnector(formattingConnector.getUuid())
                        .withFamily(SignatureFamily.PADES)
                        .withMaxLevel(SignatureLevel.SIGNED)
                        .build())
                .build();
    }
}
