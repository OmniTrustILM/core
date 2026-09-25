package com.otilm.core.cbom.asset.identity;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.otilm.api.model.core.cryptoasset.PqcVerdict;
import com.otilm.core.cbom.asset.CryptoAssetIdentityFields;
import com.otilm.core.cbom.pqc.PqcDecision;
import com.otilm.core.cbom.pqc.PqcEvaluator;
import java.util.Set;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * The slots a certificate and a key learn from the components they point at, and the keys that must not move when they
 * do.
 *
 * <p>
 * The ratified vectors never resolve the second hop, so the shape here is the one CBOM-Lens emits: a certificate, its
 * public key as its own component, and the algorithm the key names.
 */
class ReferencedSlotProjectionTest {

    private static final ObjectMapper MAPPER = new ObjectMapper();

    private final AssetNormalizer normalizer = new AssetNormalizer(IdentityTables.load());

    private final CryptoAssetIdentity identity = new CryptoAssetIdentity(normalizer);

    private static final String CERTIFICATE = """
            {
              "bom-ref": "crypto/certificate/api",
              "type": "cryptographic-asset",
              "name": "api.example.com",
              "cryptoProperties": {
                "assetType": "certificate",
                "certificateProperties": {
                  "subjectName": "CN=api.example.com",
                  "issuerName": "CN=Example Issuing CA",
                  "notValidBefore": "2025-01-01T00:00:00Z",
                  "notValidAfter": "2026-01-01T00:00:00Z",
                  "certificateFormat": "X.509",
                  "subjectPublicKeyRef": "crypto/key/api"
                }
              }
            }
            """;

    private static final String PUBLIC_KEY = """
            {
              "bom-ref": "crypto/key/api",
              "type": "cryptographic-asset",
              "name": "api.example.com",
              "cryptoProperties": {
                "assetType": "related-crypto-material",
                "relatedCryptoMaterialProperties": {
                  "type": "public-key",
                  "size": 256,
                  "format": "PEM",
                  "algorithmRef": "crypto/algorithm/ecdsa-p-256",
                  "value": "QUJD"
                }
              }
            }
            """;

    private static final String ALGORITHM = """
            {
              "bom-ref": "crypto/algorithm/ecdsa-p-256",
              "type": "cryptographic-asset",
              "name": "ECDSA-P-256",
              "cryptoProperties": {
                "assetType": "algorithm",
                "oid": "1.2.840.10045.4.3.2",
                "algorithmProperties": {
                  "primitive": "signature",
                  "curve": "P-256",
                  "parameterSetIdentifier": "256"
                }
              }
            }
            """;

    private CryptoAssetIdentity.Identity identify(String ref, String... components) throws Exception {
        var array = MAPPER.createArrayNode();
        for (String component : components) {
            array.add(MAPPER.readTree(component));
        }
        var document = MAPPER.createObjectNode();
        document.set("components", array);
        JsonNode subject = null;
        for (JsonNode component : array) {
            if (ref.equals(component.get("bom-ref").asText())) {
                subject = component;
            }
        }
        return identity.of(subject, DocumentScope.of(document, normalizer), Set.of());
    }

    private NormalizedAsset keyed(String ref, String... components) throws Exception {
        return identify(ref, components).asset();
    }

    private String key(String ref, String... components) throws Exception {
        return identify(ref, components).key();
    }

    @Test
    void aCertificateTakesTheFamilyCurveAndSizeOfTheKeyItCertifies() throws Exception {
        NormalizedAsset certificate = keyed("crypto/certificate/api", CERTIFICATE, PUBLIC_KEY, ALGORITHM);

        assertThat(certificate.family()).isEqualTo("ECDSA");
        assertThat(certificate.curve()).isEqualTo("secg/secp256r1");
        assertThat(certificate.primitive()).isEqualTo("signature");
        assertThat(certificate.parameterSet()).isEqualTo(256);
        assertThat(certificate.familySource()).isEqualTo("referenced algorithm");
    }

    /**
     * The certificate's pre-image is built from its names, validity and key material, none of which the algorithm
     * component carries, so its appearance must not move the key.
     */
    @Test
    void theAlgorithmBehindTheKeyMovesNoIdentityKey() throws Exception {
        String withoutAlgorithm = key("crypto/certificate/api", CERTIFICATE, PUBLIC_KEY);
        String withAlgorithm = key("crypto/certificate/api", CERTIFICATE, PUBLIC_KEY, ALGORITHM);

        assertThat(withAlgorithm).isEqualTo(withoutAlgorithm);
        assertThat(keyed("crypto/certificate/api", CERTIFICATE, PUBLIC_KEY).family())
                .describedAs("without the algorithm there is no family to take, and the row stays blind")
                .isNull();
    }

    /**
     * The PQC rules read a key's size slot as the size its algorithm spells and its declared size from the stored
     * properties, so the declared size must not reach the slot.
     */
    @Test
    void aKeysDeclaredSizeStaysOffItsOwnSizeSlot() throws Exception {
        NormalizedAsset key = keyed("crypto/key/api", PUBLIC_KEY);

        assertThat(key.parameterSet()).isNull();
        assertThat(key.family()).describedAs("the algorithm is not in this document").isNull();
    }

    @Test
    void aKeyTakesTheFamilyOfTheAlgorithmItNames() throws Exception {
        NormalizedAsset key = keyed("crypto/key/api", PUBLIC_KEY, ALGORITHM);

        assertThat(key.family()).isEqualTo("ECDSA");
        assertThat(key.curve()).isEqualTo("secg/secp256r1");
        assertThat(key.parameterSet()).isEqualTo(256);
    }

    @Test
    void aCertificateTakesItsKeysDeclaredSizeOverTheAlgorithmsSize() throws Exception {
        String keyDeclaring4096 = PUBLIC_KEY.replace("\"size\": 256", "\"size\": 4096");

        assertThat(keyed("crypto/certificate/api", CERTIFICATE, keyDeclaring4096, ALGORITHM).parameterSet())
                .describedAs("the nearer source of a fact wins; the algorithm states 256")
                .isEqualTo(4096);
        assertThat(keyed("crypto/key/api", keyDeclaring4096, ALGORITHM).parameterSet())
                .describedAs("the key's own slot carries the algorithm's size")
                .isEqualTo(256);
    }

    @Test
    void aCertificateReferencingTheAlgorithmDirectlyTakesItsSlots() throws Exception {
        String pointingAtAlgorithm = CERTIFICATE.replace("crypto/key/api", "crypto/algorithm/ecdsa-p-256");

        NormalizedAsset certificate = keyed("crypto/certificate/api", pointingAtAlgorithm, ALGORITHM);

        assertThat(certificate.family()).isEqualTo("ECDSA");
        assertThat(certificate.parameterSet()).isEqualTo(256);
    }

    @Test
    void aDanglingOrNonAlgorithmReferenceLeavesTheRowBlindRatherThanWrong() throws Exception {
        String keyToNowhere = PUBLIC_KEY.replace("crypto/algorithm/ecdsa-p-256", "crypto/algorithm/absent");

        NormalizedAsset key = keyed("crypto/key/api", keyToNowhere, ALGORITHM);

        assertThat(key.family()).isNull();
        assertThat(key.parameterSet()).isNull();
    }

    @Test
    void aProtocolTakesNoSlotBecauseNoneOfThemDescribeIt() throws Exception {
        String protocol = """
                {
                  "bom-ref": "crypto/protocol/tls",
                  "type": "cryptographic-asset",
                  "name": "tls",
                  "cryptoProperties": {
                    "assetType": "protocol",
                    "protocolProperties": {"type": "tls", "version": "1.2"}
                  }
                }
                """;

        NormalizedAsset keyed = keyed("crypto/protocol/tls", protocol, ALGORITHM);

        assertThat(keyed.family()).isNull();
        assertThat(keyed.curve()).isNull();
        assertThat(keyed.primitive()).isNull();
        assertThat(keyed.parameterSet()).isNull();
        assertThat(keyed.variant()).isNull();
    }

    /**
     * {@code PqcEvaluator.fromStoredRow} prefers the stored family column over the name, and a key's name yields no
     * family, so this projection deliberately moves a key's verdict from unclassifiable to its classification.
     */
    @Test
    void theProjectedFamilyChangesAKeysVerdictFromUnclassifiableToItsClassification() throws Exception {
        PqcEvaluator evaluator = new PqcEvaluator(normalizer);

        PqcDecision withoutAlgorithm = evaluator
                .evaluate(evaluator.fromStoredRow(fieldsOf(keyed("crypto/key/api", PUBLIC_KEY)), null), null);
        PqcDecision withAlgorithm = evaluator
                .evaluate(evaluator.fromStoredRow(fieldsOf(keyed("crypto/key/api", PUBLIC_KEY, ALGORITHM)), null),
                        null);

        assertThat(withoutAlgorithm.verdict()).isEqualTo(PqcVerdict.UNKNOWN);
        assertThat(withoutAlgorithm.ruleId()).isEqualTo("FAMILY-UNRESOLVED");
        assertThat(withAlgorithm.verdict())
                .describedAs("an ECDSA public key is broken by Shor, and saying so is the point of the projection")
                .isEqualTo(PqcVerdict.NOT_READY);
        assertThat(withAlgorithm.ruleId()).isEqualTo("CLASSICAL-SHOR");
    }

    /** A certificate's rule fires on the asset type before any family arm, so its verdict cannot move. */
    @Test
    void aCertificatesVerdictDoesNotMoveWhenItsKeyResolves() throws Exception {
        PqcEvaluator evaluator = new PqcEvaluator(normalizer);

        PqcDecision bare = evaluator
                .evaluate(evaluator.fromStoredRow(fieldsOf(keyed("crypto/certificate/api", CERTIFICATE)), null), null);
        PqcDecision projected = evaluator
                .evaluate(evaluator
                        .fromStoredRow(fieldsOf(keyed("crypto/certificate/api", CERTIFICATE, PUBLIC_KEY, ALGORITHM)),
                                null),
                        null);

        assertThat(projected.verdict()).isEqualTo(bare.verdict());
        assertThat(projected.ruleId()).isEqualTo(bare.ruleId()).isEqualTo("CERT-DEFERRED-V1");
    }

    private static CryptoAssetIdentityFields fieldsOf(NormalizedAsset asset) {
        return CryptoAssetIdentityFields.of(PqcEvaluator.assetTypeOf(asset.assetType()), asset);
    }

    /** Without the whitelist a key could write an arbitrary integer into its certificate's size column. */
    @Test
    void aDeclaredKeySizeOutsideTheWhitelistCostsTheSlotRatherThanTheRow() throws Exception {
        String absurd = PUBLIC_KEY.replace("\"size\": 256", "\"size\": 99999999");

        NormalizedAsset certificate = keyed("crypto/certificate/api", CERTIFICATE, absurd);

        assertThat(certificate.parameterSet()).isNull();
        assertThat(certificate.notes())
                .anyMatch(note -> note.contains("99999999") && note.contains("outside whitelist"));
    }

    /** The algorithm's size reaches the key's slot, and the key's own undersized declaration still decides. */
    @Test
    void anUndersizedSecretKeyStaysWeakUnderAnAdequateAlgorithm() throws Exception {
        String secretKey = """
                {
                  "bom-ref": "crypto/key/session",
                  "type": "cryptographic-asset",
                  "name": "session",
                  "cryptoProperties": {
                    "assetType": "related-crypto-material",
                    "relatedCryptoMaterialProperties": {
                      "type": "secret-key",
                      "size": 64,
                      "algorithmRef": "crypto/algorithm/aes-256"
                    }
                  }
                }
                """;
        String aes256 = """
                {
                  "bom-ref": "crypto/algorithm/aes-256",
                  "type": "cryptographic-asset",
                  "name": "AES-256-GCM",
                  "cryptoProperties": {
                    "assetType": "algorithm",
                    "algorithmProperties": {"primitive": "ae", "parameterSetIdentifier": "256"}
                  }
                }
                """;
        PqcEvaluator evaluator = new PqcEvaluator(normalizer);

        NormalizedAsset key = keyed("crypto/key/session", secretKey, aes256);
        PqcDecision decision = evaluator
                .evaluate(evaluator.fromStoredRow(fieldsOf(key), MAPPER.readTree(secretKey).get("cryptoProperties")),
                        null);

        assertThat(key.family()).isEqualTo("AES");
        assertThat(key.parameterSet()).isEqualTo(256);
        assertThat(decision.verdict()).isEqualTo(PqcVerdict.NOT_READY);
        assertThat(decision.ruleId()).isEqualTo("MATERIAL-SYMMETRIC-WEAK");
    }
}
