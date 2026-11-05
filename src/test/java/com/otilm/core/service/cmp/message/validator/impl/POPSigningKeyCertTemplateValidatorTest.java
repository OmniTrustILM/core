package com.otilm.core.service.cmp.message.validator.impl;

import com.otilm.api.interfaces.core.cmp.error.CmpProcessingException;
import com.otilm.api.model.common.enums.cryptography.KeyAlgorithm;
import com.otilm.core.helpers.CertificateGeneratorHelper;
import com.otilm.core.service.cmp.configurations.ConfigurationContext;
import com.otilm.core.util.CryptographyUtil;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.Security;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.RSAKeyGenParameterSpec;
import org.assertj.core.api.ThrowableAssert.ThrowingCallable;
import org.bouncycastle.asn1.cmp.PKIBody;
import org.bouncycastle.asn1.cmp.PKIFailureInfo;
import org.bouncycastle.asn1.cmp.PKIHeader;
import org.bouncycastle.asn1.cmp.PKIHeaderBuilder;
import org.bouncycastle.asn1.cmp.PKIMessage;
import org.bouncycastle.asn1.crmf.CertReqMessages;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.cert.crmf.CertificateRequestMessageBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.MockedStatic;
import org.mockito.junit.jupiter.MockitoExtension;

import static com.otilm.core.util.SignatureVerificationBoundsFixtures.rsaPublicKeyInfo;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.CALLS_REAL_METHODS;
import static org.mockito.Mockito.mockStatic;

/**
 * The proof of possession of a CRMF request is checked with the key of its certificate template, which the client
 * chooses, so the key is judged before it is built.
 */
@ExtendWith(MockitoExtension.class)
class POPSigningKeyCertTemplateValidatorTest {

    private static final String SUBJECT = "CN=cmp-client";

    @Mock
    private ConfigurationContext configuration;

    private final POPSigningKeyCertTemplateValidator validator = new POPSigningKeyCertTemplateValidator();

    @BeforeAll
    static void registerBouncyCastle() {
        Security.addProvider(new BouncyCastleProvider());
    }

    @Test
    void refusesWithoutBuildingTheKey_whenTemplateKeyIsBeyondTheBounds() throws Exception {
        // given
        SubjectPublicKeyInfo rsaKeyOf16384Bits = rsaPublicKeyInfo(PKCSObjectIdentifiers.rsaEncryption, 16384,
                RSAKeyGenParameterSpec.F4);
        PKIMessage request = initializationRequestCarrying(rsaKeyOf16384Bits, ecKeyPair());

        try (MockedStatic<CryptographyUtil> cryptography = mockStatic(CryptographyUtil.class, CALLS_REAL_METHODS)) {
            // when
            ThrowingCallable validate = () -> validator.validate(request, configuration);

            // then
            assertThatThrownBy(validate)
                    .isInstanceOfSatisfying(CmpProcessingException.class,
                            thrown -> assertThat(thrown.getFailureInfo()).isEqualTo(PKIFailureInfo.badPOP));
            cryptography.verifyNoInteractions();
        }
    }

    @Test
    void accepts_whenTemplateKeySignedTheRequest() throws Exception {
        // given
        KeyPair keyPair = ecKeyPair();
        SubjectPublicKeyInfo publicKey = SubjectPublicKeyInfo.getInstance(keyPair.getPublic().getEncoded());
        PKIMessage request = initializationRequestCarrying(publicKey, keyPair);

        // when
        Void result = validator.validate(request, configuration);

        // then
        assertThat(result).isNull();
    }

    // ── Helpers ───────────────────────────────────────────────────────────────

    /** An ir whose certificate template holds the subject and the public key, its proof of possession signed. */
    private static PKIMessage initializationRequestCarrying(SubjectPublicKeyInfo publicKey, KeyPair popSigner)
            throws Exception {
        CertificateRequestMessageBuilder certificateRequest = new CertificateRequestMessageBuilder(BigInteger.ZERO)
                .setSubject(new X500Name(SUBJECT))
                .setPublicKey(publicKey)
                .setProofOfPossessionSigningKeySigner(new JcaContentSignerBuilder("SHA256withECDSA")
                        .setProvider(BouncyCastleProvider.PROVIDER_NAME)
                        .build(popSigner.getPrivate()));
        PKIBody body = new PKIBody(PKIBody.TYPE_INIT_REQ,
                new CertReqMessages(certificateRequest.build().toASN1Structure()));
        PKIHeader header = new PKIHeaderBuilder(PKIHeader.CMP_2000, new GeneralName(new X500Name(SUBJECT)),
                new GeneralName(new X500Name("CN=ManagementCA")))
                .setTransactionID("pop-transaction".getBytes(StandardCharsets.US_ASCII))
                .build();
        return new PKIMessage(header, body);
    }

    private static KeyPair ecKeyPair() throws Exception {
        return CertificateGeneratorHelper.generateKeyPair(KeyAlgorithm.ECDSA, new ECGenParameterSpec("secp256r1"));
    }
}
