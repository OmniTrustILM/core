package com.otilm.core.key.description;

import com.otilm.api.model.common.enums.cryptography.KeyAlgorithm;
import com.otilm.api.model.common.enums.cryptography.KeyFormat;
import com.otilm.api.model.common.enums.cryptography.KeyType;
import com.otilm.core.model.crypto.KeyMaterial;
import com.otilm.core.model.crypto.ProviderKeyItem;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.spec.ECGenParameterSpec;
import java.util.Base64;
import java.util.List;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.jcajce.spec.MLDSAParameterSpec;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

import static com.otilm.core.util.builders.ProviderKeyItemBuilder.aProviderKeyItem;
import static org.assertj.core.api.Assertions.assertThat;

class ProviderKeyItemsTest {

    @Nested
    class Described {

        @Test
        void dropsTheStatedLength_whenNothingDescribesAnEcHalf() {
            // given
            var statedEcLength = 512;
            var unreadable = privateItem(KeyAlgorithm.ECDSA, statedEcLength, null);

            // when
            ProviderKeyItem described = ProviderKeyItems.described(unreadable);

            // then
            assertThat(described)
                    .extracting(ProviderKeyItem::algorithm, ProviderKeyItem::parameterSet, ProviderKeyItem::length)
                    .containsExactly(KeyAlgorithm.ECDSA, null, null);
        }

        @Test
        void keepsTheStatedLength_whenNothingDescribesAnRsaPrivateHalf() {
            // given
            var statedRsaLength = 3072;
            var unreadable = privateItem(KeyAlgorithm.RSA, statedRsaLength, null);

            // when
            ProviderKeyItem described = ProviderKeyItems.described(unreadable);

            // then
            assertThat(described.length()).isEqualTo(statedRsaLength);
        }
    }

    @Nested
    class DescribedPair {

        @Test
        void describesAPrivateHalfByItsPublicSibling_whenItsOwnKeyDataIsOpaque() throws Exception {
            // given
            var publicSibling = publicItem(ecKeyPair("secp256r1"));
            var opaquePrivate = privateItem(KeyAlgorithm.ECDSA, 256, new KeyMaterial(KeyFormat.RAW, "b3BhcXVl"));

            // when
            var described = ProviderKeyItems.describedPair(publicSibling, opaquePrivate);

            // then
            assertThat(described.privateKey())
                    .extracting(ProviderKeyItem::parameterSet, ProviderKeyItem::length)
                    .containsExactly("P-256", 256);
        }

        @Test
        void describesAPrivateHalfByItsOwnPkcs8_whenASiblingNamesAnotherCurve() throws Exception {
            // given
            var pair = ecKeyPair("secp384r1");
            var unrelatedSibling = publicItem(ecKeyPair("secp256r1"));
            var ownPkcs8 = new KeyMaterial(KeyFormat.PRKI,
                    Base64.getEncoder().encodeToString(pair.getPrivate().getEncoded()));
            var privateHalf = privateItem(KeyAlgorithm.ECDSA, null, ownPkcs8);

            // when
            var described = ProviderKeyItems.describedPair(unrelatedSibling, privateHalf);

            // then
            assertThat(described.privateKey().parameterSet()).isEqualTo("P-384");
        }

        @Test
        void sizesAPostQuantumPrivateHalfAsAPrivateKey_whenItsSiblingNamesTheParameterSet() throws Exception {
            // given
            var publicSibling = publicItem(mlDsa65KeyPair());
            var opaquePrivate = privateItem(KeyAlgorithm.MLDSA, 15616, null);

            // when
            var described = ProviderKeyItems.describedPair(publicSibling, opaquePrivate);

            // then
            assertThat(described.privateKey())
                    .extracting(ProviderKeyItem::parameterSet, ProviderKeyItem::length)
                    .containsExactly("ML-DSA-65", 32256);
        }

        @Test
        void sizesAnRsaPrivateHalfByItsSiblingsModulus_whenItsDescriptorStatesNoLength() throws Exception {
            // given
            var pair = rsaKeyPair(2048);
            var privateHalf = privateItem(KeyAlgorithm.RSA, null, storedIdentifierOf(pair));

            // when
            var described = ProviderKeyItems.describedPair(publicItem(pair), privateHalf);

            // then
            assertThat(described.privateKey().length()).isEqualTo(2048);
        }

        @Test
        void sizesAnRsaPrivateHalfByItsSiblingsModulus_whenItsDescriptorStatesAnotherLength() throws Exception {
            // given
            var pair = rsaKeyPair(2048);
            var lengthAConnectorGotWrong = 4096;
            var privateHalf = privateItem(KeyAlgorithm.RSA, lengthAConnectorGotWrong, storedIdentifierOf(pair));

            // when
            var described = ProviderKeyItems.describedPair(publicItem(pair), privateHalf);

            // then
            assertThat(described.privateKey().length()).isEqualTo(2048);
        }
    }

    @Nested
    class DescribedByAssociation {

        @Test
        void describesAPrivateHalfByItsOwnPairsSibling_whenSeveralPairsAreListed() throws Exception {
            // given
            var ownSibling = publicItem(ecKeyPair("secp384r1"), "pair-a");
            var otherPairsSibling = publicItem(ecKeyPair("secp256r1"), "pair-b");
            var privateHalf = aProviderKeyItem()
                    .withType(KeyType.PRIVATE_KEY)
                    .withAlgorithm(KeyAlgorithm.ECDSA)
                    .withLength(null)
                    .withAssociation("pair-a")
                    .build();

            // when
            List<ProviderKeyItem> described = ProviderKeyItems
                    .describedByAssociation(List.of(otherPairsSibling, privateHalf, ownSibling));

            // then
            assertThat(described).extracting(ProviderKeyItem::parameterSet).containsExactly("P-256", "P-384", "P-384");
        }

        @Test
        void describesACustomPrivateHalfByItsStatement_whenTheSiblingsDisagree() throws Exception {
            // given
            var p256 = publicItem(ecKeyPair("secp256r1"), "pair-a");
            var p521 = publicItem(ecKeyPair("secp521r1"), "pair-a");
            var customPrivate = aProviderKeyItem()
                    .withType(KeyType.PRIVATE_KEY)
                    .withAlgorithm(KeyAlgorithm.ECDSA)
                    .withLength(768)
                    .withMaterial(new KeyMaterial(KeyFormat.CUSTOM, "{\"curve.name\":\"secp384r1\"}"))
                    .withAssociation("pair-a")
                    .build();

            // when
            List<ProviderKeyItem> described = ProviderKeyItems
                    .describedByAssociation(List.of(p256, p521, customPrivate));

            // then
            assertThat(described.get(2))
                    .extracting(ProviderKeyItem::parameterSet, ProviderKeyItem::length)
                    .containsExactly(null, null);
        }

        @Test
        void describesAnItemAlone_whenItHasNoAssociation() throws Exception {
            // given
            var unassociatedSibling = publicItem(ecKeyPair("secp384r1"), null);
            var unassociatedPrivate = privateItem(KeyAlgorithm.ECDSA, null, null);

            // when
            List<ProviderKeyItem> described = ProviderKeyItems
                    .describedByAssociation(List.of(unassociatedSibling, unassociatedPrivate));

            // then
            assertThat(described.get(1).parameterSet()).isNull();
        }
    }

    // ── Helpers ───────────────────────────────────────────────────────────────

    private static ProviderKeyItem publicItem(KeyPair pair) {
        return publicItem(pair, null);
    }

    private static ProviderKeyItem publicItem(KeyPair pair, String association) {
        var spki = new KeyMaterial(KeyFormat.SPKI, Base64.getEncoder().encodeToString(pair.getPublic().getEncoded()));
        return aProviderKeyItem()
                .withType(KeyType.PUBLIC_KEY)
                .withAlgorithm(KeyAlgorithm.UNKNOWN)
                .withLength(null)
                .withMaterial(spki)
                .withAssociation(association)
                .build();
    }

    private static ProviderKeyItem privateItem(KeyAlgorithm algorithm, Integer length, KeyMaterial material) {
        return aProviderKeyItem()
                .withType(KeyType.PRIVATE_KEY)
                .withAlgorithm(algorithm)
                .withLength(length)
                .withMaterial(material)
                .build();
    }

    private static KeyMaterial storedIdentifierOf(KeyPair pair) throws Exception {
        var identifier = SubjectPublicKeyInfo.getInstance(pair.getPublic().getEncoded()).getAlgorithm();
        return new KeyMaterial(KeyFormat.ALGORITHM_IDENTIFIER,
                Base64.getEncoder().encodeToString(identifier.getEncoded()));
    }

    private static KeyPair rsaKeyPair(int bits) throws Exception {
        var generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(bits);
        return generator.generateKeyPair();
    }

    private static KeyPair ecKeyPair(String curve) throws Exception {
        var generator = KeyPairGenerator.getInstance("EC", new BouncyCastleProvider());
        generator.initialize(new ECGenParameterSpec(curve));
        return generator.generateKeyPair();
    }

    private static KeyPair mlDsa65KeyPair() throws Exception {
        var generator = KeyPairGenerator.getInstance("ML-DSA", new BouncyCastleProvider());
        generator.initialize(MLDSAParameterSpec.ml_dsa_65);
        return generator.generateKeyPair();
    }
}
