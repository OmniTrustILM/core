package com.otilm.core.key.description;

import com.otilm.api.model.common.enums.cryptography.KeyAlgorithm;
import com.otilm.api.model.common.enums.cryptography.KeyFormat;
import com.otilm.api.model.common.enums.cryptography.KeyType;
import com.otilm.core.key.description.RelatedKeyDescriber.KeyHalf;
import com.otilm.core.model.crypto.KeyMaterial;
import java.security.KeyPairGenerator;
import java.security.PublicKey;
import java.security.spec.ECGenParameterSpec;
import java.util.Base64;
import java.util.List;
import java.util.Optional;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.asn1.x9.ECNamedCurveTable;
import org.bouncycastle.asn1.x9.X962Parameters;
import org.bouncycastle.asn1.x9.X9ObjectIdentifiers;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

class RelatedKeyDescriberTest {

    @Test
    void agreesOnNoParameters_whenPublicSiblingsEncodeOneCurveDifferently() throws Exception {
        // given
        var named = SubjectPublicKeyInfo.getInstance(ecPublicKey("secp256r1").getEncoded());
        var explicit = new SubjectPublicKeyInfo(
                new AlgorithmIdentifier(X9ObjectIdentifiers.id_ecPublicKey,
                        new X962Parameters(ECNamedCurveTable.getByName("secp256r1"))),
                named.getPublicKeyData().getBytes());
        var privateHalf = new KeyHalf(KeyType.PRIVATE_KEY, KeyAlgorithm.ECDSA, null, null);
        var related = List.of(publicHalf(named), publicHalf(explicit), privateHalf);

        // when
        Optional<KeyParameters> agreed = RelatedKeyDescriber.agreedByPublicSiblings(privateHalf, related);

        // then
        assertThat(agreed).isEmpty();
    }

    @Test
    void agreesOnNoParameters_whenPublicRsaSiblingsCarryDifferentModuli() throws Exception {
        // given
        var rsa2048 = SubjectPublicKeyInfo.getInstance(rsaPublicKey(2048).getEncoded());
        var rsa1024 = SubjectPublicKeyInfo.getInstance(rsaPublicKey(1024).getEncoded());
        var privateHalf = new KeyHalf(KeyType.PRIVATE_KEY, KeyAlgorithm.RSA, null, null);
        var related = List.of(publicHalf(rsa2048), publicHalf(rsa1024), privateHalf);

        // when
        Optional<KeyParameters> agreed = RelatedKeyDescriber.agreedByPublicSiblings(privateHalf, related);

        // then
        assertThat(agreed).isEmpty();
    }

    @Test
    void withholdsTheKeyData_whenAHalfIsPrinted() {
        // given
        var storedPrivateKey = "cHJpdmF0ZSBrZXk=";
        var half = new KeyHalf(KeyType.PRIVATE_KEY, KeyAlgorithm.RSA, 2048,
                new KeyMaterial(KeyFormat.PRKI, storedPrivateKey));

        // when
        String printed = half.toString();

        // then
        assertThat(printed).doesNotContain(storedPrivateKey);
    }

    // ── Helpers ───────────────────────────────────────────────────────────────

    private static KeyHalf publicHalf(SubjectPublicKeyInfo spki) throws Exception {
        var material = new KeyMaterial(KeyFormat.SPKI, Base64.getEncoder().encodeToString(spki.getEncoded()));
        return new KeyHalf(KeyType.PUBLIC_KEY, KeyAlgorithm.UNKNOWN, null, material);
    }

    private static PublicKey ecPublicKey(String curveName) throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("EC", new BouncyCastleProvider());
        generator.initialize(new ECGenParameterSpec(curveName));
        return generator.generateKeyPair().getPublic();
    }

    private static PublicKey rsaPublicKey(int bits) throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(bits);
        return generator.generateKeyPair().getPublic();
    }
}
