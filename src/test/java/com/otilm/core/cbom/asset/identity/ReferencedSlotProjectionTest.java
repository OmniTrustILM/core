package com.otilm.core.cbom.asset.identity;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.otilm.api.model.core.cryptoasset.PqcVerdict;
import com.otilm.core.cbom.asset.CryptoAssetIdentityFields;
import com.otilm.core.cbom.pqc.PqcDecision;
import com.otilm.core.cbom.pqc.PqcEvaluator;
import java.util.Set;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;

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

    @Test
    void aKeyTakesItsOwnDeclaredSizeBeforeItsAlgorithms() throws Exception {
        NormalizedAsset key = keyed("crypto/key/api", PUBLIC_KEY);

        assertThat(key.parameterSet()).isEqualTo(256);
        assertThat(key.family()).describedAs("the algorithm is not in this document").isNull();
    }

    @Test
    void aKeyDeclaringNoSizeTakesItsAlgorithms() throws Exception {
        String unsized = PUBLIC_KEY.replace("\"size\": 256,", "");

        assertThat(keyed("crypto/key/api", unsized, ALGORITHM).parameterSet()).isEqualTo(256);
        assertThat(keyed("crypto/key/api", unsized).parameterSet()).isNull();
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
                .describedAs("the key's own slot carries its own size, as its certificate's does")
                .isEqualTo(4096);
    }

    @Test
    void aCertificateReferencingTheAlgorithmDirectlyTakesItsSlots() throws Exception {
        String pointingAtAlgorithm = CERTIFICATE.replace("crypto/key/api", "crypto/algorithm/ecdsa-p-256");

        NormalizedAsset certificate = keyed("crypto/certificate/api", pointingAtAlgorithm, ALGORITHM);

        assertThat(certificate.family()).isEqualTo("ECDSA");
        assertThat(certificate.parameterSet()).isEqualTo(256);
    }

    @Test
    void aDanglingReferenceLeavesTheRowBlindRatherThanWrong() throws Exception {
        String keyToNowhere = PUBLIC_KEY.replace("crypto/algorithm/ecdsa-p-256", "crypto/algorithm/absent");

        NormalizedAsset key = keyed("crypto/key/api", keyToNowhere, ALGORITHM);

        assertThat(key.family()).isNull();
        assertThat(key.curve()).isNull();
    }

    @Test
    void aReferenceToAnotherKeyLeavesTheRowBlindEvenWhenThatKeyCarriesAlgorithmProperties() throws Exception {
        String keyToKey = PUBLIC_KEY.replace("crypto/algorithm/ecdsa-p-256", "crypto/key/other");
        String otherKey = """
                {
                  "bom-ref": "crypto/key/other",
                  "type": "cryptographic-asset",
                  "name": "ECDSA-P-256",
                  "cryptoProperties": {
                    "assetType": "related-crypto-material",
                    "algorithmProperties": {"primitive": "signature", "curve": "P-256", "parameterSetIdentifier": "256"},
                    "relatedCryptoMaterialProperties": {"type": "private-key", "size": 256}
                  }
                }
                """;

        NormalizedAsset key = keyed("crypto/key/api", keyToKey, otherKey, ALGORITHM);

        assertThat(key.family()).isNull();
        assertThat(key.curve()).isNull();
        assertThat(key.primitive()).isNull();
    }

    @Test
    void anAlgorithmTheNormalizerRefusesCostsTheKeyItsSlotsButNotItsRow() throws Exception {
        String unstorable = ALGORITHM.replace("\"name\": \"ECDSA-P-256\"", "\"name\": \"" + "A".repeat(1025) + "\"");

        CryptoAssetIdentity.Identity key = identify("crypto/key/api", PUBLIC_KEY, unstorable);

        assertThat(key.key()).isEqualTo(key("crypto/key/api", PUBLIC_KEY));
        assertThat(key.asset().family()).isNull();
        assertThat(key.asset().curve()).isNull();
    }

    @Test
    void aKeyTakesTheAlgorithmItsRelatedAssetEntryNames() throws Exception {
        String keyIn17 = PUBLIC_KEY
                .replace("\"algorithmRef\": \"crypto/algorithm/ecdsa-p-256\",",
                        "\"relatedCryptographicAssets\": [{\"type\": \"algorithm\", \"ref\": \"crypto/algorithm/ecdsa-p-256\"}],");

        NormalizedAsset key = keyed("crypto/key/api", keyIn17, ALGORITHM);
        NormalizedAsset certificate = keyed("crypto/certificate/api", CERTIFICATE, keyIn17, ALGORITHM);

        assertThat(key.family()).isEqualTo("ECDSA");
        assertThat(key.curve()).isEqualTo("secg/secp256r1");
        assertThat(certificate.family()).isEqualTo("ECDSA");
    }

    @Test
    void aRelatedAssetEntryWinsOverTheLegacyAlgorithmRef() throws Exception {
        String keyStatingBoth = PUBLIC_KEY
                .replace("\"algorithmRef\": \"crypto/algorithm/ecdsa-p-256\",",
                        "\"algorithmRef\": \"crypto/algorithm/absent\", \"relatedCryptographicAssets\": "
                                + "[{\"type\": \"algorithm\", \"ref\": \"crypto/algorithm/ecdsa-p-256\"}],");

        assertThat(keyed("crypto/key/api", keyStatingBoth, ALGORITHM).family()).isEqualTo("ECDSA");
    }

    @Test
    void twoAlgorithmEntriesNameNoAlgorithmAndTheLegacyFieldIsNotConsulted() throws Exception {
        String ambiguous = PUBLIC_KEY
                .replace("\"algorithmRef\": \"crypto/algorithm/ecdsa-p-256\",",
                        "\"algorithmRef\": \"crypto/algorithm/ecdsa-p-256\", \"relatedCryptographicAssets\": ["
                                + "{\"type\": \"algorithm\", \"ref\": \"crypto/algorithm/ecdsa-p-256\"},"
                                + "{\"type\": \"algorithm\", \"ref\": \"crypto/algorithm/other\"}],");

        assertThat(keyed("crypto/key/api", ambiguous, ALGORITHM).family()).isNull();
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
                    "protocolProperties": {
                      "type": "tls",
                      "version": "1.2",
                      "cipherSuites": [{"name": "TLS_ECDHE_ECDSA", "algorithms": ["crypto/algorithm/ecdsa-p-256"]}],
                      "relatedCryptographicAssets": [{"type": "algorithm", "ref": "crypto/algorithm/ecdsa-p-256"}]
                    }
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

    @Test
    void theProjectedFamilyIsAFilterSlotAndMovesNoVerdict() throws Exception {
        PqcEvaluator evaluator = new PqcEvaluator(normalizer);
        NormalizedAsset key = keyed("crypto/key/api", PUBLIC_KEY, ALGORITHM);

        PqcDecision decision = evaluator.evaluate(evaluator.fromStoredRow(fieldsOf(key), null), null);

        assertThat(key.family()).isEqualTo("ECDSA");
        assertThat(decision.verdict()).isEqualTo(PqcVerdict.UNKNOWN);
        assertThat(decision.ruleId()).isEqualTo("FAMILY-UNRESOLVED");
        assertThat(decision.evaluatedFields()).doesNotContainKey("algorithmFamily");
    }

    /**
     * Half an algorithm's identity must not decide a key: a hybrid's elected family, a construction without its hash.
     */
    @ParameterizedTest(name = "{0} {1} under {3}")
    @CsvSource({
            "session,     shared-secret, 256, X25519-Kyber768,   READY,     MATERIAL-SYMMETRIC-READY",
            "session,     shared-secret, 256, X25519-ML-KEM-768, READY,     MATERIAL-SYMMETRIC-READY",
            "k,           secret-key,    256, HMAC-SHA256,       READY,     MATERIAL-SYMMETRIC-READY",
            "AES-64,      secret-key,    256, AES-256-GCM,       NOT_READY, SYMMETRIC-UNDERSIZED",
            "HMAC-RIPEMD, secret-key,    256, AES-256-GCM,       UNKNOWN,   FAMILY-AMBIGUOUS-COMPONENT",
            "HMAC-RIPEMD, secret-key,    256, HMAC-SHA256,       UNKNOWN,   FAMILY-AMBIGUOUS-COMPONENT",
            "session,     secret-key,     64, AES-256-GCM,       NOT_READY, MATERIAL-SYMMETRIC-WEAK"})
    void aKeyIsJudgedByItsOwnNameAndSizeWhateverAlgorithmItReferences(String keyName, String type, int size,
            String algorithmName, PqcVerdict verdict, String ruleId) throws Exception {
        String key = """
                {
                  "bom-ref": "crypto/key/k",
                  "type": "cryptographic-asset",
                  "name": "%s",
                  "cryptoProperties": {
                    "assetType": "related-crypto-material",
                    "relatedCryptoMaterialProperties": {"type": "%s", "size": %d, "algorithmRef": "crypto/algorithm/a"}
                  }
                }
                """.formatted(keyName, type, size);
        String algorithm = """
                {
                  "bom-ref": "crypto/algorithm/a",
                  "type": "cryptographic-asset",
                  "name": "%s",
                  "cryptoProperties": {"assetType": "algorithm", "algorithmProperties": {}}
                }
                """.formatted(algorithmName);
        PqcEvaluator evaluator = new PqcEvaluator(normalizer);
        JsonNode properties = MAPPER.readTree(key).get("cryptoProperties");

        NormalizedAsset referencing = keyed("crypto/key/k", key, algorithm);
        PqcDecision decision = evaluator.evaluate(evaluator.fromStoredRow(fieldsOf(referencing), properties), null);
        PqcDecision unreferenced = evaluator
                .evaluate(evaluator.fromStoredRow(fieldsOf(keyed("crypto/key/k", key)), properties), null);

        assertThat(referencing.family()).describedAs("the reference resolved and filled the slot").isNotNull();
        assertThat(decision.verdict()).isEqualTo(verdict).isEqualTo(unreferenced.verdict());
        assertThat(decision.ruleId()).isEqualTo(ruleId).isEqualTo(unreferenced.ruleId());
    }

    /** A certificate is decided by what it references, before any family arm, so its verdict cannot move. */
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
        assertThat(projected.ruleId()).isEqualTo(bare.ruleId()).isEqualTo("CERT-NO-KEY-RECORDED");
    }

    private static CryptoAssetIdentityFields fieldsOf(NormalizedAsset asset) {
        return CryptoAssetIdentityFields.of(PqcEvaluator.assetTypeOf(asset.assetType()), asset);
    }

    /** Without the whitelist a key could write an arbitrary integer into its certificate's size column. */
    @Test
    void aDeclaredKeySizeOutsideTheWhitelistCostsTheSlotRatherThanTheRow() throws Exception {
        String absurd = PUBLIC_KEY.replace("\"size\": 256", "\"size\": 99999999");

        NormalizedAsset certificate = keyed("crypto/certificate/api", CERTIFICATE, absurd);
        NormalizedAsset key = keyed("crypto/key/api", absurd);

        assertThat(certificate.parameterSet()).isNull();
        assertThat(certificate.notes())
                .anyMatch(note -> note.contains("99999999") && note.contains("outside whitelist"));
        assertThat(key.parameterSet()).isNull();
        assertThat(key.notes()).anyMatch(note -> note.contains("99999999") && note.contains("outside whitelist"));
    }

    /** The key's own undersized declaration decides, in its slot and in its verdict. */
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
        assertThat(key.parameterSet()).isEqualTo(64);
        assertThat(decision.verdict()).isEqualTo(PqcVerdict.NOT_READY);
        assertThat(decision.ruleId()).isEqualTo("MATERIAL-SYMMETRIC-WEAK");
    }
}
