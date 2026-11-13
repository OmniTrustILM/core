package com.otilm.core.service.est.enrollment;

import com.otilm.core.service.est.enrollment.EstKeyPairGenerator.GeneratedKey;
import com.otilm.core.service.est.message.EstError;
import com.otilm.core.service.est.message.EstException;
import com.otilm.core.util.SignatureVerificationBoundsFixtures;
import java.math.BigInteger;
import java.security.KeyPairGenerator;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.RSAKeyGenParameterSpec;
import java.util.stream.Stream;
import org.assertj.core.api.ThrowableAssert.ThrowingCallable;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.DERBitString;
import org.bouncycastle.asn1.misc.MiscObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.Attribute;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.Extensions;
import org.bouncycastle.asn1.x509.ExtensionsGenerator;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.jcajce.JcaContentVerifierProviderBuilder;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.junit.jupiter.params.provider.ValueSource;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class EstKeyPairGeneratorTest {

    private static final BouncyCastleProvider PROVIDER = new BouncyCastleProvider();
    private static final X500Name SUBJECT = new X500Name("CN=device-1,O=Example");

    @ParameterizedTest(name = "{0}")
    @MethodSource("clientKeys")
    void generatesKeyWithTheClientsAlgorithm_whenClientKeyIsSupported(String algorithm, AlgorithmParameterSpec spec)
            throws Exception {
        // given
        SubjectPublicKeyInfo clientKey = clientKeyInfo(algorithm, spec);

        // when
        GeneratedKey generated = EstKeyPairGenerator.generate(clientKey, SUBJECT, null);

        // then
        SubjectPublicKeyInfo generatedKey = SubjectPublicKeyInfo
                .getInstance(generated.keyPair().getPublic().getEncoded());
        assertThat(generatedKey.getAlgorithm()).isEqualTo(clientKey.getAlgorithm());
        assertThat(generated.request().getSubjectPublicKeyInfo()).isEqualTo(generatedKey);
    }

    @ParameterizedTest(name = "{0}")
    @MethodSource("clientKeys")
    void signsRequestWithNewKeyForSubjectAndExtensions_whenClientKeyIsSupported(String algorithm,
            AlgorithmParameterSpec spec) throws Exception {
        // given
        SubjectPublicKeyInfo clientKey = clientKeyInfo(algorithm, spec);
        Extensions requested = subjectAlternativeNames("device-1.example.com");

        // when
        GeneratedKey generated = EstKeyPairGenerator.generate(clientKey, SUBJECT, requested);

        // then
        assertThat(generated.request().getSubject()).isEqualTo(SUBJECT);
        assertThat(requestedExtensionsOf(generated)).isEqualTo(requested);
        assertThat(generated
                .request()
                .isSignatureValid(new JcaContentVerifierProviderBuilder()
                        .setProvider(PROVIDER)
                        .build(generated.keyPair().getPublic())))
                .isTrue();
    }

    @ParameterizedTest(name = "RSA {0} bits")
    @MethodSource("rsaSizes")
    void generatesRsaKeyWithPublicExponent65537_whenClientKeyIsRsa(int modulusBits) throws Exception {
        // given
        SubjectPublicKeyInfo clientKey = clientKeyInfo("RSA",
                new RSAKeyGenParameterSpec(modulusBits, BigInteger.valueOf(3)));

        // when
        GeneratedKey generated = EstKeyPairGenerator.generate(clientKey, SUBJECT, null);

        // then
        var publicKey = (RSAPublicKey) generated.keyPair().getPublic();
        assertThat(publicKey.getModulus().bitLength()).isEqualTo(modulusBits);
        assertThat(publicKey.getPublicExponent()).isEqualTo(RSAKeyGenParameterSpec.F4);
    }

    @Test
    void generatesRsaEncryptionKey_whenClientKeyIsRsaPss() throws Exception {
        // given
        SubjectPublicKeyInfo rsaPssKey = SignatureVerificationBoundsFixtures
                .rsaPublicKeyInfo(PKCSObjectIdentifiers.id_RSASSA_PSS, 2048, RSAKeyGenParameterSpec.F4);

        // when
        GeneratedKey generated = EstKeyPairGenerator.generate(rsaPssKey, SUBJECT, null);

        // then
        assertThat(generated.keyPair().getPublic().getAlgorithm()).isEqualTo("RSA");
        assertThat(((RSAPublicKey) generated.keyPair().getPublic()).getModulus().bitLength()).isEqualTo(2048);
    }

    @Test
    void buildsRequestWithoutExtensionRequest_whenNoExtensionsAreGiven() throws Exception {
        // given
        SubjectPublicKeyInfo clientKey = clientKeyInfo("Ed25519", null);

        // when
        GeneratedKey generated = EstKeyPairGenerator.generate(clientKey, SUBJECT, null);

        // then
        assertThat(generated.request().getAttributes(PKCSObjectIdentifiers.pkcs_9_at_extensionRequest)).isEmpty();
    }

    @Test
    void refusesWithBadRequest_whenRsaKeyExceedsTheBounds() throws Exception {
        // given
        int oversizeModulusBits = 8193;
        SubjectPublicKeyInfo oversizeKey = SignatureVerificationBoundsFixtures
                .rsaPublicKeyInfo(PKCSObjectIdentifiers.rsaEncryption, oversizeModulusBits, RSAKeyGenParameterSpec.F4);

        // when
        ThrowingCallable generate = () -> EstKeyPairGenerator.generate(oversizeKey, SUBJECT, null);

        // then
        assertBadRequest(generate);
    }

    @ParameterizedTest(name = "RSA {0} bits")
    @ValueSource(ints = {16, 256, 511})
    @Timeout(30)
    void refusesWithBadRequest_whenRsaModulusIsTooShortToGenerate(int modulusBits) throws Exception {
        // given
        SubjectPublicKeyInfo shortKey = SignatureVerificationBoundsFixtures
                .rsaPublicKeyInfo(PKCSObjectIdentifiers.rsaEncryption, modulusBits, RSAKeyGenParameterSpec.F4);

        // when
        ThrowingCallable generate = () -> EstKeyPairGenerator.generate(shortKey, SUBJECT, null);

        // then
        assertBadRequest(generate);
    }

    @Test
    void refusesWithBadRequest_whenKeyIsComposite() {
        // given
        var compositeKey = new SubjectPublicKeyInfo(new AlgorithmIdentifier(MiscObjectIdentifiers.id_composite_key),
                new DERBitString(new byte[]{1, 2, 3}));

        // when
        ThrowingCallable generate = () -> EstKeyPairGenerator.generate(compositeKey, SUBJECT, null);

        // then
        assertBadRequest(generate);
    }

    @Test
    void printsNoKeyMaterial_whenGeneratedKeyIsConvertedToText() throws Exception {
        // given
        GeneratedKey generated = EstKeyPairGenerator.generate(clientKeyInfo("Ed25519", null), SUBJECT, null);

        // when
        String text = generated.toString();

        // then
        assertThat(text)
                .doesNotContain(generated.keyPair().getPrivate().toString())
                .doesNotContain(generated.keyPair().getPublic().toString());
    }

    // ── Helpers ───────────────────────────────────────────────────────────────

    private static Stream<Arguments> clientKeys() {
        return Stream
                .of(Arguments.of("RSA", new RSAKeyGenParameterSpec(2048, RSAKeyGenParameterSpec.F4)),
                        Arguments.of("EC", new ECGenParameterSpec("secp256r1")),
                        Arguments.of("EC", new ECGenParameterSpec("secp384r1")),
                        Arguments.of("EC", new ECGenParameterSpec("secp521r1")),
                        Arguments.of("EC", new ECGenParameterSpec("brainpoolP256r1")), Arguments.of("Ed25519", null),
                        Arguments.of("Ed448", null), Arguments.of("ML-DSA-44", null), Arguments.of("ML-DSA-65", null),
                        Arguments.of("ML-DSA-87", null), Arguments.of("SLH-DSA-SHA2-128F", null),
                        Arguments.of("Falcon-512", null), Arguments.of("ML-DSA-44-WITH-SHA512", null),
                        Arguments.of("SLH-DSA-SHA2-128F-WITH-SHA256", null));
    }

    private static Stream<Integer> rsaSizes() {
        return Stream.of(2048, 3072, 4096);
    }

    private static SubjectPublicKeyInfo clientKeyInfo(String algorithm, AlgorithmParameterSpec spec) throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance(algorithm, PROVIDER);
        if (spec != null) {
            generator.initialize(spec);
        }
        return SubjectPublicKeyInfo.getInstance(generator.generateKeyPair().getPublic().getEncoded());
    }

    private static Extensions subjectAlternativeNames(String dnsName) throws Exception {
        var generator = new ExtensionsGenerator();
        generator
                .addExtension(Extension.subjectAlternativeName, false,
                        new GeneralNames(new GeneralName(GeneralName.dNSName, dnsName)));
        return generator.generate();
    }

    private static Extensions requestedExtensionsOf(GeneratedKey generated) {
        assertThat(generated.request().getAttributes()).hasSize(1);
        Attribute attribute = generated.request().getAttributes(PKCSObjectIdentifiers.pkcs_9_at_extensionRequest)[0];
        ASN1Encodable value = attribute.getAttrValues().getObjectAt(0);
        return Extensions.getInstance(value);
    }

    private static void assertBadRequest(ThrowingCallable generate) {
        assertThatThrownBy(generate)
                .isInstanceOfSatisfying(EstException.class, e -> assertThat(e.error()).isEqualTo(EstError.BAD_REQUEST));
    }
}
