package com.otilm.core.signing.engine.signer;

import com.otilm.api.model.common.enums.cryptography.DigestAlgorithm;
import com.otilm.api.model.common.enums.cryptography.SignatureAlgorithm;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.Signature;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.MGF1ParameterSpec;
import java.security.spec.PSSParameterSpec;
import java.util.Arrays;
import org.assertj.core.api.ThrowableAssert.ThrowingCallable;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;
import org.junit.jupiter.params.provider.ValueSource;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class PrehashedSignatureVerifierTest {

    private static final byte[] MESSAGE = "message to be signed".getBytes(StandardCharsets.UTF_8);

    private static KeyPair rsaKeys;
    private static KeyPair otherRsaKeys;
    private static KeyPair p256Keys;
    private static KeyPair p384Keys;

    @BeforeAll
    static void generateKeys() throws GeneralSecurityException {
        rsaKeys = generateRsa(2048);
        otherRsaKeys = generateRsa(2048);
        p256Keys = generateEc("secp256r1");
        p384Keys = generateEc("secp384r1");
    }

    @ParameterizedTest
    @EnumSource(value = SignatureAlgorithm.class,
            names = {
                    "SHA256_WITH_RSA",
                    "SHA384_WITH_RSA",
                    "SHA512_WITH_RSA",
                    "SHA256_WITH_RSA_PSS",
                    "SHA384_WITH_RSA_PSS",
                    "SHA512_WITH_RSA_PSS",
                    "SHA256_WITH_ECDSA",
                    "SHA384_WITH_ECDSA",
                    "SHA512_WITH_ECDSA"})
    void returnsTrue_whenTheJdkSignedTheMessage(SignatureAlgorithm algorithm) throws Exception {
        // given
        KeyPair keys = pickKeysFor(algorithm);
        byte[] signature = signWithJdk(algorithm, keys.getPrivate(), MESSAGE);

        // when
        boolean verified = PrehashedSignatureVerifier
                .verifies(algorithm, keys.getPublic(), computeDigest(algorithm, MESSAGE), signature);

        // then
        assertThat(verified).isTrue();
    }

    @Test
    void returnsTrue_whenP256SignsASha512Digest() throws Exception {
        // given
        SignatureAlgorithm digestLongerThanTheCurve = SignatureAlgorithm.SHA512_WITH_ECDSA;
        byte[] signature = signWithJdk(digestLongerThanTheCurve, p256Keys.getPrivate(), MESSAGE);

        // when
        boolean verified = PrehashedSignatureVerifier
                .verifies(digestLongerThanTheCurve, p256Keys.getPublic(),
                        computeDigest(digestLongerThanTheCurve, MESSAGE), signature);

        // then
        assertThat(verified).isTrue();
    }

    @ParameterizedTest
    @ValueSource(strings = {"brainpoolP256r1", "secp224r1"})
    void returnsTrue_whenTheCurveIsOneSunEcCannotCompute(String curve) throws Exception {
        // given — SunEC cannot sign on these curves, so BouncyCastle makes the signature
        var bouncyCastle = new BouncyCastleProvider();
        var generator = KeyPairGenerator.getInstance("EC", bouncyCastle);
        generator.initialize(new ECGenParameterSpec(curve));
        KeyPair keys = generator.generateKeyPair();
        var signer = Signature.getInstance("SHA256withECDSA", bouncyCastle);
        signer.initSign(keys.getPrivate());
        signer.update(MESSAGE);
        byte[] signature = signer.sign();
        SignatureAlgorithm algorithm = SignatureAlgorithm.SHA256_WITH_ECDSA;

        // when
        boolean verified = PrehashedSignatureVerifier
                .verifies(algorithm, keys.getPublic(), computeDigest(algorithm, MESSAGE), signature);

        // then
        assertThat(verified).isTrue();
    }

    @Test
    void returnsFalse_whenTheRsaKeyIsTooSmallForThePssParameters() throws Exception {
        // given — PSS with SHA-512 and a 64-byte salt needs a modulus of at least 1034 bits
        KeyPair rsa1024Keys = generateRsa(1024);
        SignatureAlgorithm algorithm = SignatureAlgorithm.SHA512_WITH_RSA_PSS;
        byte[] signatureOfTheModulusLength = new byte[128];

        // when
        boolean verified = PrehashedSignatureVerifier
                .verifies(algorithm, rsa1024Keys.getPublic(), computeDigest(algorithm, MESSAGE),
                        signatureOfTheModulusLength);

        // then
        assertThat(verified).isFalse();
    }

    @ParameterizedTest
    @EnumSource(value = SignatureAlgorithm.class,
            names = {
                    "SHA256_WITH_RSA",
                    "SHA384_WITH_RSA",
                    "SHA512_WITH_RSA",
                    "SHA256_WITH_RSA_PSS",
                    "SHA384_WITH_RSA_PSS",
                    "SHA512_WITH_RSA_PSS",
                    "SHA256_WITH_ECDSA",
                    "SHA384_WITH_ECDSA",
                    "SHA512_WITH_ECDSA"})
    void returnsFalse_whenTheDigestWasHashedAgain(SignatureAlgorithm algorithm) throws Exception {
        // given — a provider that ignored the mode signs the digest bytes as data
        KeyPair keys = pickKeysFor(algorithm);
        byte[] digest = computeDigest(algorithm, MESSAGE);
        byte[] signatureOverHashedDigest = signWithJdk(algorithm, keys.getPrivate(), digest);

        // when
        boolean verified = PrehashedSignatureVerifier
                .verifies(algorithm, keys.getPublic(), digest, signatureOverHashedDigest);

        // then
        assertThat(verified).isFalse();
    }

    @Test
    void returnsFalse_whenAnotherKeySigned() throws Exception {
        // given
        SignatureAlgorithm algorithm = SignatureAlgorithm.SHA256_WITH_RSA;
        byte[] signatureByOtherKey = signWithJdk(algorithm, otherRsaKeys.getPrivate(), MESSAGE);

        // when
        boolean verified = PrehashedSignatureVerifier
                .verifies(algorithm, rsaKeys.getPublic(), computeDigest(algorithm, MESSAGE), signatureByOtherKey);

        // then
        assertThat(verified).isFalse();
    }

    @ParameterizedTest
    @EnumSource(value = SignatureAlgorithm.class,
            names = {"SHA256_WITH_RSA", "SHA256_WITH_RSA_PSS", "SHA256_WITH_ECDSA"})
    void returnsFalse_whenTheSignatureBytesAreMalformed(SignatureAlgorithm algorithm) throws Exception {
        // given
        byte[] threeBytes = {1, 2, 3};

        // when
        boolean verified = PrehashedSignatureVerifier
                .verifies(algorithm, pickKeysFor(algorithm).getPublic(), computeDigest(algorithm, MESSAGE), threeBytes);

        // then
        assertThat(verified).isFalse();
    }

    @Test
    void returnsFalse_whenTheEcdsaSignatureHoldsANonIntegerElement() {
        // given
        SignatureAlgorithm algorithm = SignatureAlgorithm.SHA256_WITH_ECDSA;
        byte[] sequenceHoldingAnOctetString = {0x30, 0x06, 0x02, 0x01, 0x01, 0x04, 0x01, 0x01};

        // when
        boolean verified = PrehashedSignatureVerifier
                .verifies(algorithm, p256Keys.getPublic(), new byte[32], sequenceHoldingAnOctetString);

        // then
        assertThat(verified).isFalse();
    }

    @Test
    void returnsFalse_whenThePssSaltLengthDiffers() throws Exception {
        // given
        SignatureAlgorithm algorithm = SignatureAlgorithm.SHA256_WITH_RSA_PSS;
        int saltShorterThanTheDigest = 20;
        Signature signer = Signature.getInstance("RSASSA-PSS");
        signer
                .setParameter(
                        new PSSParameterSpec("SHA-256", "MGF1", MGF1ParameterSpec.SHA256, saltShorterThanTheDigest, 1));
        signer.initSign(rsaKeys.getPrivate());
        signer.update(MESSAGE);
        byte[] signature = signer.sign();

        // when
        boolean verified = PrehashedSignatureVerifier
                .verifies(algorithm, rsaKeys.getPublic(), computeDigest(algorithm, MESSAGE), signature);

        // then
        assertThat(verified).isFalse();
    }

    @ParameterizedTest
    @EnumSource(value = SignatureAlgorithm.class, names = {"SHA256_WITH_RSA", "SHA256_WITH_RSA_PSS"})
    void returnsFalse_whenTheRsaSignatureIsShorterThanTheModulus(SignatureAlgorithm algorithm) throws Exception {
        // given
        SignedMessage signedWithLeadingZero = signUntilTheSignatureStartsWithZero(algorithm);
        byte[] signature = signedWithLeadingZero.signature();
        byte[] strippedOfItsLeadingZero = Arrays.copyOfRange(signature, 1, signature.length);

        // when
        boolean verified = PrehashedSignatureVerifier
                .verifies(algorithm, rsaKeys.getPublic(), computeDigest(algorithm, signedWithLeadingZero.message()),
                        strippedOfItsLeadingZero);

        // then
        assertThat(verified).isFalse();
    }

    @ParameterizedTest
    @EnumSource(value = SignatureAlgorithm.class,
            names = {"SHA256_WITH_RSA", "SHA256_WITH_RSA_PSS", "SHA256_WITH_ECDSA"})
    void returnsFalse_whenTheKeyDoesNotFitTheCodesFamily(SignatureAlgorithm algorithm) throws Exception {
        // given — an RSA code is checked with an EC key and the ECDSA code with an RSA key
        KeyPair keyOfAnotherFamily = algorithm == SignatureAlgorithm.SHA256_WITH_ECDSA ? rsaKeys : p256Keys;
        byte[] signature = signWithJdk(algorithm, pickKeysFor(algorithm).getPrivate(), MESSAGE);

        // when
        boolean verified = PrehashedSignatureVerifier
                .verifies(algorithm, keyOfAnotherFamily.getPublic(), computeDigest(algorithm, MESSAGE), signature);

        // then
        assertThat(verified).isFalse();
    }

    @Test
    void throwsIllegalArgument_whenTheCodeIsOutsideTheBound() {
        // given
        SignatureAlgorithm outsideTheBound = SignatureAlgorithm.ED25519;
        byte[] anyBytes = {1};

        // when
        ThrowingCallable verify = () -> PrehashedSignatureVerifier
                .verifies(outsideTheBound, rsaKeys.getPublic(), anyBytes, anyBytes);

        // then
        assertThatThrownBy(verify).isInstanceOf(IllegalArgumentException.class);
    }

    // ── Helpers ───────────────────────────────────────────────────────────────

    private static KeyPair generateRsa(int modulusBits) throws GeneralSecurityException {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(modulusBits);
        return generator.generateKeyPair();
    }

    private static KeyPair generateEc(String curve) throws GeneralSecurityException {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("EC");
        generator.initialize(new ECGenParameterSpec(curve));
        return generator.generateKeyPair();
    }

    private static KeyPair pickKeysFor(SignatureAlgorithm algorithm) {
        String code = algorithm.name();
        if (code.endsWith("ECDSA")) {
            return code.startsWith("SHA256") ? p256Keys : p384Keys;
        }
        return rsaKeys;
    }

    private static byte[] computeDigest(SignatureAlgorithm algorithm, byte[] data) throws GeneralSecurityException {
        DigestAlgorithm digest = PrehashedSigning.digestAlgorithm(algorithm);
        return MessageDigest.getInstance(digest.getProviderName()).digest(data);
    }

    private static byte[] signWithJdk(SignatureAlgorithm algorithm, PrivateKey key, byte[] data)
            throws GeneralSecurityException {
        String code = algorithm.name();
        Signature signature;
        if (code.endsWith("RSA_PSS")) {
            DigestAlgorithm digest = PrehashedSigning.digestAlgorithm(algorithm);
            signature = Signature.getInstance("RSASSA-PSS");
            signature
                    .setParameter(new PSSParameterSpec(digest.getProviderName(), "MGF1",
                            new MGF1ParameterSpec(digest.getProviderName()), digest.getDigestSizeBytes(), 1));
        } else {
            String hash = code.substring(0, "SHA256".length());
            signature = Signature.getInstance(hash + (code.endsWith("ECDSA") ? "withECDSA" : "withRSA"));
        }
        signature.initSign(key);
        signature.update(data);
        return signature.sign();
    }

    // About one RSA signature in 256 starts with a zero byte. PKCS#1 v1.5 signatures are deterministic, so each
    // attempt signs a different message.
    private static SignedMessage signUntilTheSignatureStartsWithZero(SignatureAlgorithm algorithm)
            throws GeneralSecurityException {
        for (int attempt = 0; attempt < 10_000; attempt++) {
            byte[] message = ("message " + attempt).getBytes(StandardCharsets.UTF_8);
            byte[] signature = signWithJdk(algorithm, rsaKeys.getPrivate(), message);
            if (signature[0] == 0) {
                return new SignedMessage(message, signature);
            }
        }
        throw new IllegalStateException("No signature started with a zero byte in 10000 attempts");
    }

    private record SignedMessage(byte[] message, byte[] signature) {
    }
}
