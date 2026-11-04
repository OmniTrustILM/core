package com.otilm.core.service.cmp.message.validator.impl;

import com.otilm.api.interfaces.core.cmp.error.CmpProcessingException;
import com.otilm.api.model.common.enums.cryptography.KeyAlgorithm;
import com.otilm.core.helpers.CertificateGeneratorHelper;
import com.otilm.core.service.cmp.configurations.ConfigurationContext;
import com.otilm.core.util.CertificateUtil;
import java.security.KeyPair;
import java.security.Security;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.RSAKeyGenParameterSpec;
import org.assertj.core.api.ThrowableAssert.ThrowingCallable;
import org.bouncycastle.asn1.cmp.PKIFailureInfo;
import org.bouncycastle.asn1.cmp.PKIMessage;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.MockedStatic;
import org.mockito.junit.jupiter.MockitoExtension;

import static com.otilm.core.service.cmp.message.validator.impl.SignatureProtectedMessageFixtures.onExplicitCurve;
import static com.otilm.core.service.cmp.message.validator.impl.SignatureProtectedMessageFixtures.signatureProtectedMessage;
import static com.otilm.core.util.SignatureVerificationBoundsFixtures.rsaPublicKeyInfo;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.CALLS_REAL_METHODS;
import static org.mockito.Mockito.mockStatic;
import static org.mockito.Mockito.never;

/**
 * Signature-based protection is checked with the key of the first certificate that the message carries. A client
 * supplies that certificate in a request, so its key is judged before the certificate is parsed, since parsing it
 * builds the key.
 */
@ExtendWith(MockitoExtension.class)
class ProtectionSignatureValidatorTest {

    @Mock
    private ConfigurationContext configuration;

    private final ProtectionSignatureValidator requestValidator = new ProtectionSignatureValidator(true);
    private final ProtectionSignatureValidator responseValidator = new ProtectionSignatureValidator(false);

    @BeforeAll
    static void registerBouncyCastle() {
        Security.addProvider(new BouncyCastleProvider());
    }

    @Test
    void refusesWithoutParsingTheCertificate_whenClientCertificateKeyIsBeyondTheBounds() throws Exception {
        // given
        SubjectPublicKeyInfo rsaKeyOf16384Bits = rsaPublicKeyInfo(PKCSObjectIdentifiers.rsaEncryption, 16384,
                RSAKeyGenParameterSpec.F4);
        PKIMessage request = signatureProtectedMessage(ecKeyPair(), rsaKeyOf16384Bits);

        try (MockedStatic<CertificateUtil> certificates = mockStatic(CertificateUtil.class, CALLS_REAL_METHODS)) {
            // when
            ThrowingCallable validate = () -> requestValidator.validate(request, configuration);

            // then
            assertThatThrownBy(validate)
                    .isInstanceOfSatisfying(CmpProcessingException.class,
                            thrown -> assertThat(thrown.getFailureInfo()).isEqualTo(PKIFailureInfo.badAlg));
            certificates.verify(() -> CertificateUtil.getX509Certificate(any(byte[].class)), never());
        }
    }

    @Test
    void accepts_whenClientSignedWithTheKeyOfItsCertificate() throws Exception {
        // given
        KeyPair signerKeyPair = ecKeyPair();
        SubjectPublicKeyInfo signerKey = SubjectPublicKeyInfo.getInstance(signerKeyPair.getPublic().getEncoded());
        PKIMessage request = signatureProtectedMessage(signerKeyPair, signerKey);

        // when
        ThrowingCallable validate = () -> requestValidator.validate(request, configuration);

        // then
        assertThatCode(validate).doesNotThrowAnyException();
    }

    @Test
    void acceptsWithoutJudgingTheKey_whenCorePlatformSignedTheMessage() throws Exception {
        // given — a response signed with the key of the profile's signing certificate, whatever its algorithm
        KeyPair signerKeyPair = ecKeyPair();
        PKIMessage response = signatureProtectedMessage(signerKeyPair, onExplicitCurve(signerKeyPair, "secp256r1"));

        // when
        ThrowingCallable validate = () -> responseValidator.validate(response, configuration);

        // then
        assertThatCode(validate).doesNotThrowAnyException();
    }

    // ── Helpers ───────────────────────────────────────────────────────────────

    private static KeyPair ecKeyPair() throws Exception {
        return CertificateGeneratorHelper.generateKeyPair(KeyAlgorithm.ECDSA, new ECGenParameterSpec("secp256r1"));
    }
}
