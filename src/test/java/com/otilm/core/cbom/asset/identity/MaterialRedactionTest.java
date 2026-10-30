package com.otilm.core.cbom.asset.identity;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Set;
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

    private static final String PEM = "-----BEGIN PRIVATE KEY-----MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQC";

    /** A schema-valid fingerprint content: 64 hex characters, as every corpus fingerprint carries. */
    private static final String HEX64 = "3942447fac867ae5cdb3229b658f4d483942447fac867ae5cdb3229b658f4d48";

    private static final String FINGERPRINT = "{\"alg\":\"SHA-256\",\"content\":\"" + HEX64 + "\"}";

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

    /**
     * The allowlist is the schema's high-entropy vocabulary, matched on the lookup key like every other type.
     *
     * <p>
     * Every entry, in its schema spelling or a folded one: an accidental omission from the set fails <em>closed and
     * silently</em> -- the type loses its published digest and nothing else says so -- so a pin that reached seven of
     * the entries left six able to vanish unnoticed.
     */
    @ParameterizedTest
    @ValueSource(strings = {
            "private-key",
            "publicKey",
            "SECRET_KEY",
            "key",
            "ciphertext",
            "signature",
            "initialization-vector",
            "InitializationVector",
            "nonce",
            "seed",
            "salt",
            "shared secret",
            "tag"})
    void highEntropyMaterialPublishesItsDigest(String type) {
        assertThat(redact(type, "QUJDRA==").publishedDigest()).isNotNull();
    }

    /**
     * The schema values outside the allowlist fail closed, and {@code digest} is one of them on purpose.
     *
     * <p>
     * {@code additional-data} is arbitrary producer content. {@code digest} has exactly the entropy of whatever it was
     * taken over, so publishing {@code sha256(md5(password))} is a password-verification oracle one step removed -- the
     * same argument that withholds a scanner's fingerprint of a password. The rest are the ones a person typed.
     */
    @ParameterizedTest
    @ValueSource(strings = {"additional-data", "digest", "password", "credential", "token", "other", "unknown"})
    void everyOtherSchemaTypeFailsClosed(String type) {
        MaterialRedaction redaction = redact(type, "QUJDRA==");

        assertThat(redaction.publishedDigest()).isNull();
        assertThat(redaction.findings()).anySatisfy(finding -> assertThat(finding).contains("digest withheld"));
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
     *
     * <p>
     * The gate is every type whose digest is withheld plus the publishable secret types, so {@code passphrase},
     * {@code pin}, {@code api-key} and the rest are here: an eight-element denylist beside the allowlist left the loud
     * finding off for every spelling outside the eight while the value was redacted quietly.
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
            "shared_secret",
            "password",
            "credential",
            "token",
            "passphrase",
            "pin",
            "api-key",
            "jwt",
            "secret",
            "session-token",
            "pwd",
            "symmetric-key",
            "key-pair",
            "other",
            "unknown",
            "additional-data",
            "digest"})
    void anInlinedSecretIsReportedAsAnIngestFinding(String type) {
        assertThat(redact(type, SECRET).findings())
                .anySatisfy(
                        finding -> assertThat(finding).contains("producer inlined a value on material type " + type));
    }

    /** The only quiet types are the ones the platform can vouch for as high-entropy and not secret. */
    @ParameterizedTest
    @ValueSource(strings = {"public-key", "ciphertext", "signature", "initialization-vector", "nonce", "salt", "tag"})
    void aPublishableNonSecretValueIsNotCalledExfiltration(String type) {
        assertThat(redact(type, SECRET).findings()).isEmpty();
    }

    /** A value with no type fails closed like {@code unknown}, and the finding says so rather than printing null. */
    @Test
    void anInlinedValueWithNoTypeIsReported() {
        MaterialRedaction redaction = redactMaterial("{\"value\":\"" + SECRET + "\"}");

        assertThat(redaction.findings())
                .anySatisfy(finding -> assertThat(finding)
                        .contains("producer inlined a value on material type (absent) under member value"))
                .noneSatisfy(finding -> assertThat(finding).contains("null"));
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
        MaterialRedaction redaction = redactMaterial(
                "{\"type\":\"public-key\",\"fingerprint\":{\"content\":\"" + HEX64 + "\"}}");

        assertThat(redaction.storedPayload().at("/relatedCryptoMaterialProperties/fingerprint/content").asText())
                .isEqualTo(HEX64);
        assertThat(redaction.findings()).isEmpty();
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
        MaterialRedaction redaction = redactMaterial("{\"type\":\"private-key\",\"fingerprint\":" + FINGERPRINT + "}");

        assertThat(redaction.storedPayload().at("/relatedCryptoMaterialProperties/fingerprint/content").asText())
                .isEqualTo(HEX64);
        assertThat(redaction.storedPayload().at("/relatedCryptoMaterialProperties/fingerprint/alg").asText())
                .isEqualTo("SHA-256");
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
                        .contains("members outside the contracted shape dropped")
                        .contains("relatedCryptographicAssets[0].digest")
                        .contains("relatedCryptographicAssets[1]"));
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

    /**
     * A plaintext beside a valid fingerprint is dropped, and the fingerprint survives without it.
     *
     * <p>
     * {@code isObject()} was the whole shape test, so the object was kept wholesale: a private key under a third member
     * of an otherwise well-formed fingerprint was stored on all thirteen publishable types with no finding, while the
     * same PEM under a top-level {@code pem} was dropped and raised. The object is now projected onto the schema's
     * {@code hash}: {@code alg} and {@code content}, nothing else.
     */
    @Test
    void aPlaintextBesideAValidFingerprintIsDroppedAndTheFingerprintKept() {
        MaterialRedaction redaction = redactMaterial("{\"type\":\"private-key\",\"fingerprint\":"
                + "{\"alg\":\"SHA-256\",\"content\":\"" + HEX64 + "\",\"pem\":\"" + PEM + "\"}}");

        assertThat(redaction.storedPayload().toString()).doesNotContain(PEM);
        assertThat(redaction.storedPayload().at("/relatedCryptoMaterialProperties/fingerprint/content").asText())
                .isEqualTo(HEX64);
        assertThat(redaction.storedPayload().at("/relatedCryptoMaterialProperties/fingerprint/pem").isMissingNode())
                .isTrue();
        assertThat(redaction.findings())
                .anySatisfy(finding -> assertThat(finding)
                        .contains("members outside the contracted shape dropped")
                        .contains("fingerprint.pem"));
    }

    /** Every object shape that can file a plaintext under a fingerprint, on publishable types. */
    @ParameterizedTest
    @ValueSource(strings = {
            "{\"pem\":\"<PEM>\"}",
            "{\"alg\":\"SHA-256\",\"content\":\"<PEM>\"}",
            "{\"alg\":\"<PEM>\",\"content\":\"<HEX>\"}",
            "{\"nested\":{\"deeper\":{\"pem\":\"<PEM>\"}}}",
            "{\"list\":[\"<PEM>\"]}",
            "{\"content\":{\"pem\":\"<PEM>\"}}"})
    void noFingerprintShapeCarriesAPlaintextIntoStorage(String fingerprint) {
        String shape = fingerprint.replace("<PEM>", PEM).replace("<HEX>", HEX64);
        for (String type : List.of("private-key", "public-key", "secret-key", "nonce")) {
            MaterialRedaction redaction = redactMaterial("{\"type\":\"" + type + "\",\"fingerprint\":" + shape + "}");

            assertThat(redaction.storedPayload().toString()).describedAs(type).doesNotContain(PEM);
            assertThat(redaction.findings())
                    .describedAs(type)
                    .anySatisfy(finding -> assertThat(finding).contains("fingerprint"));
        }
    }

    /**
     * The schema's {@code hash-content} pattern decides what a fingerprint content is. Anything else under the name is
     * an unrestricted string, and a fingerprint without a content is not a fingerprint at all.
     */
    @ParameterizedTest
    @CsvSource({
            "aabb, false",
            "AA:BB:CC:DD, false",
            "3942447fac867ae5cdb3229b658f4d483942447fac867ae5cdb3229b658f4d4, false",
            "3942447fac867ae5cdb3229b658f4d48, true",
            "3942447fac867ae5cdb3229b658f4d483942447f, true",
            "3942447fac867ae5cdb3229b658f4d483942447fac867ae5cdb3229b658f4d48, true",
            "3942447FAC867AE5CDB3229B658F4D483942447FAC867AE5CDB3229B658F4D48, true"})
    void onlyASchemaShapedContentIsAFingerprint(String content, boolean kept) {
        MaterialRedaction redaction = redactMaterial(
                "{\"type\":\"public-key\",\"fingerprint\":{\"alg\":\"SHA-256\",\"content\":\"" + content + "\"}}");

        JsonNode stored = redaction.storedPayload().at("/relatedCryptoMaterialProperties/fingerprint");
        if (kept) {
            assertThat(stored.get("content").asText()).isEqualTo(content);
            assertThat(redaction.findings()).isEmpty();
        } else {
            assertThat(stored.isMissingNode()).isTrue();
            assertThat(redaction.findings())
                    .anySatisfy(finding -> assertThat(finding).contains("fingerprint.content").contains("fingerprint"));
        }
    }

    /**
     * The algorithm name is admitted on its lookup key and stored as the producer spelled it; a stranger is dropped.
     */
    @Test
    void theFingerprintAlgorithmIsTheSchemaEnumerationOnItsLookupKey() {
        MaterialRedaction folded = redactMaterial(
                "{\"type\":\"public-key\",\"fingerprint\":{\"alg\":\"sha256\",\"content\":\"" + HEX64 + "\"}}");
        MaterialRedaction stranger = redactMaterial(
                "{\"type\":\"public-key\",\"fingerprint\":{\"alg\":\"SHA256withRSA\",\"content\":\"" + HEX64 + "\"}}");

        assertThat(folded.storedPayload().at("/relatedCryptoMaterialProperties/fingerprint/alg").asText())
                .isEqualTo("sha256");
        assertThat(stranger.storedPayload().at("/relatedCryptoMaterialProperties/fingerprint/alg").isMissingNode())
                .isTrue();
        assertThat(stranger.storedPayload().at("/relatedCryptoMaterialProperties/fingerprint/content").asText())
                .isEqualTo(HEX64);
        assertThat(stranger.findings()).anySatisfy(finding -> assertThat(finding).contains("fingerprint.alg"));
    }

    /**
     * {@code securedBy} is the second object-valued member, and it is contracted by name, so nothing looked inside it.
     * It is projected onto the schema's {@code mechanism} and {@code algorithmRef}, on every type.
     */
    @ParameterizedTest
    @ValueSource(strings = {"password", "private-key", "public-key", "other"})
    void aPlaintextInsideSecuredByIsDroppedAndTheMechanismKept(String type) {
        MaterialRedaction redaction = redactMaterial("{\"type\":\"" + type + "\",\"securedBy\":{\"mechanism\":\"HSM\","
                + "\"algorithmRef\":\"a1\",\"pem\":\"" + PEM + "\",\"nested\":{\"pem\":\"" + PEM + "\"}}}");

        assertThat(redaction.storedPayload().toString()).doesNotContain(PEM);
        assertThat(redaction.storedPayload().at("/relatedCryptoMaterialProperties/securedBy/mechanism").asText())
                .isEqualTo("HSM");
        assertThat(redaction.storedPayload().at("/relatedCryptoMaterialProperties/securedBy/algorithmRef").asText())
                .isEqualTo("a1");
        assertThat(redaction.findings())
                .anySatisfy(finding -> assertThat(finding)
                        .contains("members outside the contracted shape dropped")
                        .contains("securedBy.nested")
                        .contains("securedBy.pem"));
    }

    /** A {@code securedBy} that is a string is not a mechanism, and on a secret type it is called what it is. */
    @Test
    void aTextualSecuredByOnASecretTypeIsDroppedAndReportedLoudly() {
        MaterialRedaction redaction = redactMaterial("{\"type\":\"private-key\",\"securedBy\":\"" + PEM + "\"}");

        assertThat(redaction.storedPayload().toString()).doesNotContain(PEM);
        assertThat(redaction.findings())
                .anySatisfy(finding -> assertThat(finding)
                        .contains("producer inlined a value on material type private-key")
                        .contains("under member securedBy"));
    }

    /**
     * A contracted name is not a contracted member unless the value has the schema's shape.
     *
     * <p>
     * Admitting the name alone kept whatever sat under it, and a container can hold a plaintext at any depth under any
     * name -- {@code id}, {@code size}, {@code format} and every date member stored one with no finding. A string in
     * the integer slot is not a size either.
     */
    @Test
    void aContractedNameCarryingTheWrongShapeIsDropped() {
        MaterialRedaction redaction = redactMaterial("{\"type\":\"public-key\",\"id\":{\"pem\":\"" + PEM + "\"},"
                + "\"state\":[\"" + PEM + "\"],\"size\":\"" + PEM + "\",\"format\":\"PEM\",\"creationDate\":123,"
                + "\"relatedCryptographicAssets\":{\"ref\":\"a1\"}}");

        assertThat(redaction.storedPayload().toString()).doesNotContain(PEM);
        JsonNode stored = redaction.storedPayload().get("relatedCryptoMaterialProperties");
        assertThat(stored.properties().stream().map(Map.Entry::getKey)).containsExactlyInAnyOrder("type", "format");
        assertThat(redaction.findings())
                .anySatisfy(finding -> assertThat(finding)
                        .contains("uncontracted members dropped from the stored payload")
                        .contains("creationDate, id, relatedCryptographicAssets, size, state"));
    }

    /** A number is a size, whatever its width. */
    @Test
    void aNumericSizeSurvivesAndAStringSizeDoesNot() {
        assertThat(redactMaterial("{\"type\":\"public-key\",\"size\":2048}")
                .storedPayload()
                .at("/relatedCryptoMaterialProperties/size")
                .asInt()).isEqualTo(2048);
        assertThat(redactMaterial("{\"type\":\"public-key\",\"size\":\"2048\"}")
                .storedPayload()
                .at("/relatedCryptoMaterialProperties/size")
                .isMissingNode()).isTrue();
    }

    /**
     * The class, not the instance: a plaintext under any kept member name, in any container shape, on a secret type, a
     * publishable one and a low-entropy one, never reaches the stored payload and never goes silently.
     *
     * <p>
     * Before the shape joined the contract, 2 328 cells of a 3 168-cell sweep of this form stored the PEM with zero
     * findings. The string shape is deliberately not in this sweep: a string in a schema string slot is admitted by the
     * contract itself, and closing that class takes a content rule this class does not have.
     */
    @Test
    void noKeptMemberStoresAPlaintextInAnyContainerShape() {
        List<String> members = List
                .of("type", "id", "state", "algorithmRef", "creationDate", "activationDate", "updateDate",
                        "expirationDate", "size", "format", "securedBy", "fingerprint", "relatedCryptoMaterialType",
                        "relatedCryptographicAssets", "value");
        List<String> shapes = List
                .of("{\"pem\":\"<PEM>\"}", "{\"alg\":\"SHA-256\",\"content\":\"<HEX>\",\"pem\":\"<PEM>\"}",
                        "{\"mechanism\":\"HSM\",\"pem\":\"<PEM>\"}", "{\"nested\":{\"deeper\":{\"pem\":\"<PEM>\"}}}",
                        "{\"list\":[\"<PEM>\"]}", "[\"<PEM>\"]", "[{\"ref\":\"a1\",\"pem\":\"<PEM>\"}]");
        List<String> leaked = new ArrayList<>();
        for (String type : List.of("private-key", "public-key", "password", "nonce")) {
            for (String member : members) {
                for (String shape : shapes) {
                    MaterialRedaction redaction = redactMaterial("{\"type\":\"" + type + "\",\"" + member + "\":"
                            + shape.replace("<PEM>", PEM).replace("<HEX>", HEX64) + "}");
                    if (redaction.storedPayload().toString().contains(PEM) || redaction.findings().isEmpty()) {
                        leaked.add(type + " / " + member + " / " + shape);
                    }
                }
            }
        }
        assertThat(leaked).isEmpty();
    }

    /**
     * The invariant the storage side rests on: after redaction the stored material block holds no producer-chosen name
     * below the top level. Every container is one of the four this class knows, and every member inside is a schema
     * member holding a scalar.
     */
    @Test
    void theStoredMaterialBlockHoldsNoProducerChosenNameBelowTheTopLevel() {
        MaterialRedaction redaction = redactMaterial("{\"type\":\"private-key\",\"value\":\"" + SECRET + "\","
                + "\"id\":\"k1\",\"size\":2048,\"format\":\"PEM\",\"fingerprint\":{\"alg\":\"SHA-256\",\"content\":\""
                + HEX64 + "\",\"x\":{\"pem\":\"" + PEM + "\"}},\"securedBy\":{\"mechanism\":\"HSM\",\"y\":[\"" + PEM
                + "\"]},\"relatedCryptographicAssets\":[{\"ref\":\"a1\",\"z\":{\"pem\":\"" + PEM + "\"}}],"
                + "\"labels\":{\"pem\":\"" + PEM + "\"}}");
        Set<String> containers = Set.of("value", "fingerprint", "securedBy", "relatedCryptographicAssets");
        Set<String> innerMembers = Set
                .of("redacted", "length", "alg", "content", "mechanism", "algorithmRef", "ref", "type");

        JsonNode stored = redaction.storedPayload().get("relatedCryptoMaterialProperties");
        stored.properties().forEach(member -> {
            JsonNode value = member.getValue();
            if (!value.isContainerNode()) {
                return;
            }
            assertThat(containers).describedAs("container under %s", member.getKey()).contains(member.getKey());
            List<JsonNode> objects = value.isArray() ? value.valueStream().toList() : List.of(value);
            objects.forEach(object -> object.properties().forEach(inner -> {
                assertThat(innerMembers).describedAs("%s.%s", member.getKey(), inner.getKey()).contains(inner.getKey());
                assertThat(inner.getValue().isValueNode())
                        .describedAs("%s.%s is a scalar", member.getKey(), inner.getKey())
                        .isTrue();
            }));
        });
        assertThat(redaction.storedPayload().toString()).doesNotContain(PEM).doesNotContain(SECRET);
    }

    private static MaterialRedaction redactMaterial(String material) {
        return MaterialRedaction.of(read("{\"relatedCryptoMaterialProperties\":" + material + "}"));
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
