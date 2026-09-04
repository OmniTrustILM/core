package com.otilm.core.cbom.asset.identity;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.junit.jupiter.params.provider.ValueSource;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * The redaction proof: no material value survives to anything that stores, keys, logs or serves it.
 *
 * <p>
 * The property under test is an ordering one. Redaction runs before identity, persistence and logging can observe the
 * payload, so these assertions check the <em>output payload</em> for the plaintext rather than checking that some
 * caller remembered to redact.
 */
class MaterialRedactionTest {

    private static final ObjectMapper MAPPER = new ObjectMapper();

    private static final String SECRET = "s3cr3t-key-material";

    @Test
    void thePlaintextNeverReachesTheStoredPayload() {
        MaterialRedaction redaction = redact("public-key", SECRET);

        assertThat(CanonicalJson.canonicalize(redaction.storedPayload())).doesNotContain(SECRET);
        assertThat(redaction.storedPayload().toString()).doesNotContain(SECRET);
        assertThat(redaction.keyedPayload().toString())
                .describedAs("the value carries its envelope on both sides of the split")
                .doesNotContain(SECRET);
    }

    /**
     * An inlined plaintext under any other member name is dropped from storage, for every type.
     *
     * <p>
     * The allowlist used to run only for low-entropy material and the value redaction keys on the single exact member
     * name {@code value}, so the protection ran opposite to the severity of the exposure:
     * {@code {"type":"password","Value":"hunter2"}} was dropped and reported, while a private key inlined under
     * {@code pem} was stored verbatim with no finding at all.
     */
    @ParameterizedTest
    @CsvSource({
            "private-key,pem",
            "private-key,Value",
            "secret-key,content",
            "shared-secret,data",
            "seed,secret",
            "key,privateKey",
            "public-key,pem"})
    void anInlinedPlaintextUnderAnyMemberIsDroppedFromStorage(String type, String member) {
        MaterialRedaction redaction = MaterialRedaction
                .of(read("{\"relatedCryptoMaterialProperties\":{\"type\":\"" + type + "\",\"" + member + "\":\""
                        + SECRET + "\"}}"));

        assertThat(redaction.storedPayload().toString()).doesNotContain(SECRET);
        assertThat(redaction.findings())
                .anySatisfy(finding -> assertThat(finding).contains("uncontracted members dropped").contains(member));
    }

    /**
     * The keyed payload keeps every member the producer stated, because R2 names the whole of what a hash may strip.
     *
     * <p>
     * Dropping storage's uncontracted members from the hashed projection moved {@code mat:backstop} away from the
     * reference for any material carrying one -- measured as 5 corpus rows and one ratified vector -- so the two
     * payloads had to part company. Nothing the storage allowlist does can move an identity key any more.
     */
    @Test
    void theKeyedPayloadKeepsWhatStorageDrops() {
        MaterialRedaction redaction = MaterialRedaction
                .of(read("{\"relatedCryptoMaterialProperties\":{\"type\":\"password\",\"keyType\":\"aes\"}}"));

        assertThat(redaction.keyedPayload().at("/relatedCryptoMaterialProperties/keyType").asText()).isEqualTo("aes");
        assertThat(redaction.storedPayload().at("/relatedCryptoMaterialProperties/keyType").isMissingNode()).isTrue();
    }

    /**
     * The 1.7 reference array is stored, exactly as its 1.6 spelling is.
     *
     * <p>
     * {@code relatedCryptographicAssets} renames {@code algorithmRef}, and its omission from the allowlist dropped it
     * from storage on 1.7 documents while the 1.6 spelling survived -- the parity hazard R2 exists to prevent, inverted
     * onto storage, on 5 corpus rows whose finding then misdescribed a reference array as a possible digest.
     */
    @Test
    void bothSpellingsOfTheReferenceArrayAreStored() {
        MaterialRedaction redaction = MaterialRedaction
                .of(read("{\"relatedCryptoMaterialProperties\":{\"type\":\"other\",\"algorithmRef\":\"a1\","
                        + "\"relatedCryptographicAssets\":[{\"ref\":\"a1\"}]}}"));

        assertThat(redaction.storedPayload().at("/relatedCryptoMaterialProperties/algorithmRef").asText())
                .isEqualTo("a1");
        assertThat(redaction
                .storedPayload()
                .at("/relatedCryptoMaterialProperties/relatedCryptographicAssets/0/ref")
                .asText()).isEqualTo("a1");
    }

    @Test
    void theCallersInputIsNotMutated() {
        JsonNode properties = read(
                "{\"relatedCryptoMaterialProperties\":{\"type\":\"public-key\",\"value\":\"" + SECRET + "\"}}");

        MaterialRedaction.of(properties);

        assertThat(properties.at("/relatedCryptoMaterialProperties/value").asText())
                .describedAs("redaction returns a copy; a caller holding the original must be unaffected")
                .isEqualTo(SECRET);
    }

    /**
     * The published digest is withheld for low-entropy material, and the identity digest is not.
     *
     * <p>
     * An unsalted SHA-256 of a password or a token is rainbow-table reversible, so publishing it in a payload that is
     * served back is the same leak one step removed. The identity digest still exists, because the identity key is a
     * hash of a whole pre-image and is never exposed on any API -- it is what keeps two different passwords at one
     * source coordinate apart.
     *
     * <p>
     * {@code passphrase}, {@code pin}, {@code api-key} and {@code jwt} are here because a five-entry denylist let every
     * one of them through: the type vocabulary is the producer's to invent, so the rule is an allowlist of the types
     * that are high-entropy by construction and an unrecognised spelling is withheld like {@code unknown}.
     */
    @ParameterizedTest
    @ValueSource(strings = {
            "password",
            "token",
            "credential",
            "PASSWORD",
            "passphrase",
            "pin",
            "api-key",
            "jwt",
            "session-token",
            "secret",
            "symmetric-key"})
    void lowEntropyMaterialPublishesNoDigestButStillKeysApart(String type) {
        MaterialRedaction redaction = MaterialRedaction
                .of(read("{\"relatedCryptoMaterialProperties\":{\"type\":\"" + type + "\",\"value\":\"hunter2\","
                        + "\"fingerprint\":{\"alg\":\"sha-256\",\"content\":\"f52fbd32b2b3b86f\"}}}"));

        assertThat(redaction.publishedDigest()).isNull();
        assertThat(redaction.identityDigest()).isNotNull().hasSize(64);
        assertThat(redaction.storedPayload().at("/relatedCryptoMaterialProperties/value/length").asInt()).isEqualTo(7);
        assertThat(redaction.storedPayload().at("/relatedCryptoMaterialProperties/value/redacted").asBoolean())
                .isTrue();
        assertThat(redaction.storedPayload().at("/relatedCryptoMaterialProperties/value/sha256").isMissingNode())
                .isTrue();
        assertThat(redaction.storedPayload().toString())
                .describedAs("the producer's own digest of the value is as reversible as the one withheld")
                .doesNotContain("f52fbd32b2b3b86f");
        assertThat(redaction.findings()).anySatisfy(finding -> assertThat(finding).contains("digest withheld"));
    }

    /** The allowlist is the schema's high-entropy vocabulary, matched on the lookup key like every other type. */
    @ParameterizedTest
    @ValueSource(strings = {"private-key", "publicKey", "SECRET_KEY", "shared secret", "nonce", "salt", "ciphertext"})
    void highEntropyMaterialPublishesItsDigest(String type) {
        assertThat(redact(type, "QUJDRA==").publishedDigest()).isNotNull();
    }

    @Test
    void twoDifferentPasswordsAtOneCoordinateStillKeyApart() {
        assertThat(redact("password", "one").identityDigest()).isNotEqualTo(redact("password", "two").identityDigest());
    }

    @Test
    void publishableMaterialCarriesTheContractedRedactionEnvelope() {
        MaterialRedaction redaction = redact("public-key", "QUJDRA==");

        assertThat(redaction.publishedDigest()).isEqualTo(redaction.identityDigest());
        assertThat(redaction.storedPayload().at("/relatedCryptoMaterialProperties/value/redacted").asBoolean())
                .isTrue();
        assertThat(redaction.storedPayload().at("/relatedCryptoMaterialProperties/value/length").asInt()).isEqualTo(8);
        assertThat(redaction.storedPayload().at("/relatedCryptoMaterialProperties/value/sha256").isMissingNode())
                .isTrue();
        assertThat(redaction.storedPayload().at("/relatedCryptoMaterialProperties/value/$redacted").isMissingNode())
                .isTrue();
    }

    /** Fails closed: guessing wrong on an unknown type would publish a reversible digest. */
    @Test
    void anAbsentMaterialTypeIsTreatedAsLowEntropy() {
        JsonNode properties = read("{\"relatedCryptoMaterialProperties\":{\"value\":\"whatever\"}}");

        MaterialRedaction redaction = MaterialRedaction.of(properties);

        assertThat(redaction.publishedDigest()).isNull();
        assertThat(redaction.identityDigest()).isNotNull();
    }

    /**
     * A producer inlining a value on a type that should never carry one has exfiltrated key material into a document
     * the platform then aggregates estate-wide. It is raised, not silently cleaned up.
     */
    @ParameterizedTest
    @ValueSource(strings = {
            "private-key",
            "secret-key",
            "shared-secret",
            "seed",
            "key",
            "privateKey",
            "private_key",
            "PRIVATE KEY",
            "shared_secret"})
    void anInlinedSecretIsReportedAsAnIngestFinding(String type) {
        assertThat(redact(type, SECRET).findings())
                .anySatisfy(finding -> assertThat(finding).contains("producer inlined a value"));
    }

    @Test
    void aNonStringValueIsDroppedRatherThanKept() {
        JsonNode properties = read("{\"relatedCryptoMaterialProperties\":{\"type\":\"secret-key\",\"value\":123}}");

        MaterialRedaction redaction = MaterialRedaction.of(properties);

        assertThat(redaction.storedPayload().at("/relatedCryptoMaterialProperties/value").isMissingNode()).isTrue();
        assertThat(redaction.identityDigest()).isNull();
        assertThat(redaction.findings()).contains("non-string material value dropped");
    }

    /**
     * Length counts code points, because the reference counts characters and the length is served back in the payload.
     * A UTF-16 count would report 2 for one astral character.
     */
    @Test
    void lengthCountsCodePointsNotUtf16Units() {
        assertThat(redact("public-key", "😀").valueLength()).isEqualTo(1);
    }

    @Test
    void theValueIsHashedVerbatimWithNoDecodeOrTrim() {
        assertThat(redact("public-key", " AAAA ").identityDigest())
                .describedAs("normalizing first would make identity depend on the normalizer")
                .isEqualTo(IdentityDigests.sha256Hex(" AAAA "));
    }

    @Test
    void propertiesWithNoMaterialBlockPassThroughUntouched() {
        JsonNode properties = read("{\"assetType\":\"algorithm\",\"algorithmProperties\":{\"primitive\":\"hash\"}}");

        MaterialRedaction redaction = MaterialRedaction.of(properties);

        assertThat(CanonicalJson.canonicalize(redaction.storedPayload()))
                .isEqualTo(CanonicalJson.canonicalize(properties));
        assertThat(redaction.findings()).isEmpty();
    }

    @Test
    void anAbsentPropertiesBlockYieldsAnEmptyPayloadRatherThanFailing() {
        MaterialRedaction redaction = MaterialRedaction.of(null);

        assertThat(CanonicalJson.canonicalize(redaction.storedPayload())).isEqualTo("{}");
        assertThat(redaction.identityDigest()).isNull();
    }

    /**
     * Every shape of a digest-bearing member goes for low-entropy material, not only the one covered shape.
     *
     * <p>
     * A secret scanner fingerprints what it found so it can dedupe findings across runs, and that digest is exactly as
     * reversible as the one the envelope withholds. Testing {@code isObject() && has("content")} and returning
     * otherwise let a string, an array, an object keyed {@code sha256} and a nested object each carry an unsalted
     * SHA-256 of a password into the served payload with no finding raised.
     */
    @ParameterizedTest
    @ValueSource(strings = {
            "\"sha256:5e884898da280471\"",
            "[\"sha256:5e884898da280471\"]",
            "{\"sha256\":\"5e884898da280471\"}",
            "{\"x\":{\"content\":\"5e884898da280471\"}}",
            "{\"content\":\"5e884898da280471\"}"})
    void everyFingerprintShapeIsWithheldForLowEntropyMaterial(String fingerprint) {
        MaterialRedaction redaction = MaterialRedaction
                .of(read("{\"relatedCryptoMaterialProperties\":{\"type\":\"password\",\"fingerprint\":" + fingerprint
                        + "}}"));

        assertThat(redaction.storedPayload().toString()).doesNotContain("5e884898da280471");
        assertThat(redaction.findings()).anySatisfy(finding -> assertThat(finding).contains("fingerprint"));
    }

    /**
     * The member name is not enumerable, so the rule is an allowlist.
     *
     * <p>
     * None of these is a CycloneDX field -- they are all producer extensions, and a two-name withhold list let eight of
     * ten carry an unsalted SHA-256 of a password into the served payload with no finding at all.
     */
    @ParameterizedTest
    @ValueSource(strings = {
            "hash",
            "hashes",
            "sha256",
            "checksum",
            "thumbprint",
            "md5",
            "fingerprints",
            "Fingerprint",
            "fingerprint",
            "digest"})
    void anyUncontractedMemberIsDroppedForLowEntropyMaterial(String member) {
        MaterialRedaction redaction = MaterialRedaction
                .of(read("{\"relatedCryptoMaterialProperties\":{\"type\":\"password\",\"" + member
                        + "\":\"5e884898da280471\"}}"));

        assertThat(redaction.storedPayload().toString()).doesNotContain("5e884898da280471");
        assertThat(redaction.findings())
                .anySatisfy(finding -> assertThat(finding).contains("uncontracted members dropped").contains(member));
    }

    /** A contracted member is not an extension: the allowlist must not eat the pipeline's own fields. */
    @Test
    void everyContractedMemberSurvivesLowEntropyMaterial() {
        MaterialRedaction redaction = MaterialRedaction
                .of(read("{\"relatedCryptoMaterialProperties\":{\"type\":\"password\",\"id\":\"k1\","
                        + "\"state\":\"active\",\"format\":\"raw\",\"size\":256,\"securedBy\":{\"mechanism\":\"HSM\"},"
                        + "\"algorithmRef\":\"a1\",\"creationDate\":\"2026-01-01T00:00:00Z\"}}"));

        assertThat(redaction.storedPayload().at("/relatedCryptoMaterialProperties/id").asText()).isEqualTo("k1");
        assertThat(redaction.storedPayload().at("/relatedCryptoMaterialProperties/size").asInt()).isEqualTo(256);
        assertThat(redaction.storedPayload().at("/relatedCryptoMaterialProperties/securedBy/mechanism").asText())
                .isEqualTo("HSM");
        assertThat(redaction.findings())
                .noneSatisfy(finding -> assertThat(finding).contains("uncontracted members dropped"));
    }

    /**
     * The withheld member goes whole, so a sibling cannot carry the digest through.
     *
     * <p>
     * Removing only the recognised {@code content} trusted whatever sat beside it: the decoy went and the nested digest
     * was stored.
     */
    @Test
    void aSiblingCannotCarryTheWithheldDigestThrough() {
        MaterialRedaction redaction = MaterialRedaction
                .of(read("{\"relatedCryptoMaterialProperties\":{\"type\":\"password\",\"fingerprint\":"
                        + "{\"alg\":\"sha-256\",\"content\":\"decoy\",\"x\":{\"content\":\"5e884898da280471\"}}}}"));

        assertThat(redaction.storedPayload().toString()).doesNotContain("5e884898da280471").doesNotContain("decoy");
        assertThat(redaction.storedPayload().at("/relatedCryptoMaterialProperties/fingerprint").isMissingNode())
                .isTrue();
    }

    /** The sibling {@code digest} member carries the same hazard and the same rule. */
    @Test
    void aBareDigestMemberIsWithheldToo() {
        MaterialRedaction redaction = MaterialRedaction
                .of(read("{\"relatedCryptoMaterialProperties\":{\"type\":\"password\","
                        + "\"digest\":\"5e884898da280471\"}}"));

        assertThat(redaction.storedPayload().toString()).doesNotContain("5e884898da280471");
        assertThat(redaction.findings()).anySatisfy(finding -> assertThat(finding).contains("digest"));
    }

    /** Publishable material keeps its fingerprint: the withhold rule is about low-entropy types only. */
    @Test
    void aPublishableTypeKeepsItsFingerprint() {
        MaterialRedaction redaction = MaterialRedaction
                .of(read("{\"relatedCryptoMaterialProperties\":{\"type\":\"public-key\","
                        + "\"fingerprint\":{\"content\":\"aabb\"}}}"));

        assertThat(redaction.storedPayload().toString()).contains("aabb");
    }

    /**
     * A block carrying only contracted members raises nothing, so the finding list stays a signal rather than noise.
     */
    @Test
    void anAbsentFingerprintRaisesNoFinding() {
        MaterialRedaction redaction = redact("password", "hunter2");

        assertThat(redaction.findings())
                .noneSatisfy(finding -> assertThat(finding).contains("uncontracted members dropped"));
    }

    /**
     * Benign metadata on a secret type is dropped without being called exfiltration.
     *
     * <p>
     * The severe finding used to fire for every dropped member name, so a producer's flag, count or nested object was
     * reported as confirmed key material -- a false positive on the loudest finding this class emits. It now reads the
     * value: a non-blank textual scalar could be inlined material, and a number could not.
     */
    @Test
    void benignMetadataOnASecretTypeIsNotCalledExfiltration() {
        MaterialRedaction redaction = MaterialRedaction
                .of(read("{\"relatedCryptoMaterialProperties\":{\"type\":\"private-key\",\"rotationCount\":3,"
                        + "\"managed\":true,\"labels\":{\"team\":\"pki\"},\"note\":\"  \"}}"));

        assertThat(redaction.findings())
                .anySatisfy(finding -> assertThat(finding).contains("uncontracted members dropped"))
                .noneSatisfy(finding -> assertThat(finding).contains("producer inlined a value"));
        assertThat(redaction.storedPayload().at("/relatedCryptoMaterialProperties/rotationCount").isMissingNode())
                .isTrue();
    }

    /**
     * The two unrestricted members are dropped and reported on a secret type, whatever its entropy.
     *
     * <p>
     * The report and the drop asked two different questions, and aligning them onto the drop's looser set switched the
     * exfiltration finding off for exactly the two members able to hold whatever a producer puts there: a PEM under
     * {@code relatedCryptoMaterialType} or {@code fingerprint} on a {@code private-key} was stored verbatim with no
     * finding, while the same PEM under {@code pem} was dropped and raised. Both now ask one question. The long type
     * spelling is read by nothing, so dropping it on a secret type loses nothing; a fingerprint that is a string is not
     * a fingerprint.
     */
    @ParameterizedTest
    @ValueSource(strings = {"relatedCryptoMaterialType", "fingerprint"})
    void anUnrestrictedMemberOnASecretTypeIsDroppedAndReported(String member) {
        MaterialRedaction redaction = MaterialRedaction
                .of(read("{\"relatedCryptoMaterialProperties\":{\"type\":\"private-key\",\"" + member + "\":\"" + SECRET
                        + "\"}}"));

        assertThat(redaction.storedPayload().toString()).doesNotContain(SECRET);
        assertThat(redaction.storedPayload().at("/relatedCryptoMaterialProperties/" + member).isMissingNode()).isTrue();
        assertThat(redaction.findings())
                .anySatisfy(finding -> assertThat(finding)
                        .contains("producer inlined a value on material type private-key")
                        .contains("under member " + member));
    }

    /**
     * A fingerprint in its schema shape stays stored on a secret type: it is the discriminator the
     * {@code mat:fingerprint} tier keys on, irreversible for high-entropy material, and 443 corpus private keys carry
     * one. Dropping it by name would have cost every one of those served payloads its fingerprint for no gain.
     */
    @Test
    void aFingerprintObjectOnASecretTypeStaysStoredAndIsNotCalledExfiltration() {
        MaterialRedaction redaction = MaterialRedaction
                .of(read("{\"relatedCryptoMaterialProperties\":{\"type\":\"private-key\","
                        + "\"fingerprint\":{\"alg\":\"sha-256\",\"content\":\"aabb\"}}}"));

        assertThat(redaction.storedPayload().at("/relatedCryptoMaterialProperties/fingerprint/content").asText())
                .isEqualTo("aabb");
        assertThat(redaction.findings()).isEmpty();
    }

    /**
     * A nested member of the reference array cannot carry a digest into storage.
     *
     * <p>
     * The array is allowlisted by its top-level name and the drop iterates top-level names, so each entry was kept
     * whole and {@code [{"ref":"a1","digest":"…"}]} carried that digest into the stored payload. The argument for an
     * allowlist does not stop at depth one, so the entries are projected onto their contracted shape.
     */
    @Test
    void aNestedMemberOfTheReferenceArrayCannotCarryADigest() {
        MaterialRedaction redaction = MaterialRedaction
                .of(read("{\"relatedCryptoMaterialProperties\":{\"type\":\"password\","
                        + "\"relatedCryptographicAssets\":[{\"ref\":\"a1\",\"type\":\"public-key\","
                        + "\"digest\":\"5e884898da280471\"},\"not-an-object\"]}}"));

        assertThat(redaction.storedPayload().toString()).doesNotContain("5e884898da280471");
        assertThat(redaction.storedPayload().at("/relatedCryptoMaterialProperties/relatedCryptographicAssets").size())
                .describedAs("an entry that is no object states no reference and is not projected")
                .isEqualTo(1);
        assertThat(redaction
                .storedPayload()
                .at("/relatedCryptoMaterialProperties/relatedCryptographicAssets/0/ref")
                .asText()).isEqualTo("a1");
        assertThat(redaction
                .storedPayload()
                .at("/relatedCryptoMaterialProperties/relatedCryptographicAssets/0/type")
                .asText()).isEqualTo("public-key");
        assertThat(redaction.keyedPayload().toString())
                .describedAs("the keyed projection keeps every member R2 does not strip")
                .contains("5e884898da280471");
        assertThat(redaction.findings())
                .anySatisfy(finding -> assertThat(finding)
                        .contains("uncontracted members dropped from relatedCryptographicAssets entries")
                        .contains("digest"));
    }

    /**
     * The long type spelling is an unrestricted extension, so it survives only where a digest may be published.
     *
     * <p>
     * Retaining it for every type defeated the withhold rule through the exemption meant to preserve fidelity: a
     * {@code password} component carrying the password's digest under {@code relatedCryptoMaterialType} was stored and
     * served.
     */
    @Test
    void theLongTypeSpellingIsWithheldForLowEntropyMaterial() {
        MaterialRedaction lowEntropy = MaterialRedaction
                .of(read("{\"relatedCryptoMaterialProperties\":{\"type\":\"password\","
                        + "\"relatedCryptoMaterialType\":\"5e884898da280471\"}}"));
        MaterialRedaction publishable = MaterialRedaction
                .of(read("{\"relatedCryptoMaterialProperties\":{\"type\":\"public-key\","
                        + "\"relatedCryptoMaterialType\":\"publicKey\"}}"));

        assertThat(lowEntropy.storedPayload().toString()).doesNotContain("5e884898da280471");
        assertThat(lowEntropy.keyedPayload().toString())
                .describedAs("the keyed projection keeps every member R2 does not strip")
                .contains("5e884898da280471");
        assertThat(
                publishable.storedPayload().at("/relatedCryptoMaterialProperties/relatedCryptoMaterialType").asText())
                .isEqualTo("publicKey");
    }

    /**
     * The exfiltration finding names the member, so the severe case is not reported as the generic one.
     *
     * <p>
     * It used to fire only for the exact member {@code value}, so a private key inlined under {@code pem} -- the worse
     * of the two -- raised only the generic uncontracted-members line, and a consumer filtering on the specific text
     * would have missed it.
     */
    @Test
    void theExfiltrationFindingNamesTheMemberThatCarriedTheKey() {
        MaterialRedaction redaction = MaterialRedaction
                .of(read(
                        "{\"relatedCryptoMaterialProperties\":{\"type\":\"private-key\",\"pem\":\"" + SECRET + "\"}}"));

        assertThat(redaction.findings())
                .anySatisfy(finding -> assertThat(finding)
                        .contains("producer inlined a value on material type private-key")
                        .contains("under member pem"));
    }

    private static MaterialRedaction redact(String type, String value) {
        return MaterialRedaction
                .of(read("{\"relatedCryptoMaterialProperties\":{\"type\":\"" + type + "\",\"value\":" + quote(value)
                        + "}}"));
    }

    private static String quote(String value) {
        try {
            return MAPPER.writeValueAsString(value);
        } catch (JsonProcessingException e) {
            throw new IllegalArgumentException(value, e);
        }
    }

    private static JsonNode read(String json) {
        try {
            return MAPPER.readTree(json);
        } catch (JsonProcessingException e) {
            throw new IllegalArgumentException("test fixture is not JSON: " + json, e);
        }
    }
}
