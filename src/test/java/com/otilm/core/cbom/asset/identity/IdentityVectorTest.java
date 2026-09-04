package com.otilm.core.cbom.asset.identity;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.otilm.core.serialization.ObjectMapperFactory;
import java.io.IOException;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;
import java.util.stream.Stream;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * The ratified byte-level conformance instrument, run against this implementation.
 *
 * <p>
 * This suite is the reason the identity chain can be trusted, and it exists because a partition cannot check a hash.
 * The gold scenarios that accompany these vectors express expectations as <em>groupings</em> of components into rows,
 * which is what lets one suite drive any implementation -- and it is why an earlier proof-of-concept round passed 62 of
 * 62 scenarios while carrying 66 unresolved guesses. Two implementations can agree on every grouping and still write
 * different keys for one asset, at which point they can never share a {@code crypto_asset} table.
 *
 * <p>
 * Each vector therefore carries its <b>pre-image</b> as well as its digest. A mismatched hash tells an implementer only
 * that something differs; a mismatched pre-image names the slot. The three hashed slots -- the distinguished-name
 * composite, the cipher-suite token list and the occurrence triples -- publish their inner strings for the same reason,
 * after one round spent 768 guesses on the composite with only its digest to go on.
 *
 * <p>
 * <b>What this suite cannot see.</b> Every vector wraps its component in a document of its own, which is what makes the
 * set portable. That also means a cross-component reference resolves only through the vector's own {@code refTargets},
 * and document-scoped refutation has almost nothing to refute. Portability and coverage are in direct conflict here,
 * and the resolution is not to widen these vectors: it is that the corpus differential -- run outside the repository
 * against the reference kernel, because the corpus is third-party -- covers what they cannot. Do not read a green run
 * here as covering reference resolution or refutation.
 */
class IdentityVectorTest {

    private static final String VECTORS = "cbom/identity-key-vectors.json";

    private static JsonNode vectorFile;
    private static AssetNormalizer normalizer;
    private static CryptoAssetIdentity identity;

    /**
     * The ingest mapper, not a private one. This runner enabled {@code USE_BIG_DECIMAL_FOR_FLOATS}, which
     * {@code ObjectMapperFactory.storage()} does not: inert while no vector carries a non-integer literal, and the day
     * one did it would have parsed as a {@code DecimalNode} here and a {@code DoubleNode} in production.
     */
    @BeforeAll
    static void loadOnce() throws IOException {
        ObjectMapper mapper = ObjectMapperFactory.storage();
        try (InputStream stream = IdentityVectorTest.class.getClassLoader().getResourceAsStream(VECTORS)) {
            assertThat(stream).describedAs("the ratified vectors must be on the test classpath").isNotNull();
            vectorFile = mapper.readTree(stream);
        }
        normalizer = new AssetNormalizer(IdentityTables.load());
        identity = new CryptoAssetIdentity(normalizer);
    }

    static Stream<Vector> vectors() throws IOException {
        loadOnce();
        List<Vector> vectors = new ArrayList<>();
        for (JsonNode vector : vectorFile.get("vectors")) {
            vectors.add(new Vector(vector.get("id").asText(), vector));
        }
        return vectors.stream();
    }

    /** Named so a failure report says which vector broke rather than which index. */
    record Vector(String id, JsonNode node) {
        @Override
        public String toString() {
            return id;
        }
    }

    @ParameterizedTest
    @MethodSource("vectors")
    void theIdentityMatchesTheRatifiedBytes(Vector vector) {
        JsonNode component = vector.node().get("component");
        JsonNode expected = vector.node().get("expected");
        DocumentScope scope = DocumentScope.of(documentAround(vector.node()), normalizer);

        CryptoAssetIdentity.Identity actual = identity.of(component, scope, Set.of());

        // The pre-image is asserted FIRST and separately. When both differ, the pre-image is the assertion that names
        // the offending slot, and a report that leads with the digest tells the reader nothing they can act on.
        assertThat(actual.preImage())
                .describedAs("pre-image for %s -- %s", vector.id(), vector.node().path("why").asText())
                .isEqualTo(expected.get("preImage").asText());
        assertThat(actual.key())
                .describedAs("identity key for %s", vector.id())
                .isEqualTo(expected.get("identityKey").asText());
        assertThat(actual.step())
                .describedAs("chain step for %s", vector.id())
                .isEqualTo(expected.get("chainStep").asText());
    }

    /**
     * A vector on a tier that hashes an inner string must publish it: without the inner pre-image a mismatched digest
     * names no slot, which is what cost one round 768 guesses. The requirement is asserted, because the silent return
     * this used to take on an absent {@code innerPreImages} let a hashed-tier vector without one pass as covered.
     */
    @ParameterizedTest
    @MethodSource("vectors")
    void everyHashedSlotMatchesTheStringItHashes(Vector vector) {
        JsonNode inner = vector.node().get("expected").get("innerPreImages");
        if (inner == null || inner.isNull()) {
            assertThat(vector.node().get("expected").get("chainStep").asText())
                    .describedAs("%s hashes an inner string and must publish it as innerPreImages", vector.id())
                    .isNotIn(ChainStep.CRT_DN_COMPOSITE.label(), ChainStep.PRT_TYPE_VERSION_SUITES.label(),
                            ChainStep.PRT_TYPE_OCCURRENCE.label(), ChainStep.MAT_OCCURRENCE.label());
            return;
        }
        JsonNode component = vector.node().get("component");
        DocumentScope scope = DocumentScope.of(documentAround(vector.node()), normalizer);
        JsonNode properties = MaterialRedaction.of(component.get("cryptoProperties")).keyedPayload();

        if (inner.hasNonNull("dnComposite")) {
            assertThat(identity.dnPreImage(properties, scope))
                    .describedAs("distinguished-name composite pre-image for %s", vector.id())
                    .isEqualTo(inner.get("dnComposite").asText());
        }
        if (inner.hasNonNull("cipherSuites")) {
            assertThat(CipherSuites.tokens(properties, scope.refutedSuiteCodes()))
                    .describedAs("cipher-suite token list for %s", vector.id())
                    .isEqualTo(inner.get("cipherSuites").asText());
        }
        if (inner.hasNonNull("occurrences")) {
            assertThat(Occurrences.triples(component))
                    .describedAs("occurrence triples for %s", vector.id())
                    .isEqualTo(inner.get("occurrences").asText());
        }
    }

    /**
     * The vector set is a fixed artifact, so its size is asserted rather than trusted.
     *
     * <p>
     * A suite whose case count can fall silently is worse than no suite: making a corpus directory-discovered once
     * orphaned a lookup here, the count dropped by two, and the document was updated without anyone asking why. A
     * falling case count is a failure until explained.
     */
    @Test
    void theWholeRatifiedSetIsRun() {
        assertThat(vectorFile.get("vectors")).hasSize(vectorFile.get("vectorCount").asInt()).hasSize(269);
    }

    /**
     * Every chain step the implementation can produce must have at least one vector behind it.
     *
     * <p>
     * Coverage is enumerated from the tiers rather than inferred from a count. Generated coverage covers the shapes a
     * generator happens to produce, and a branch nobody's corpus exercises stays invisible to it -- 295 of one round's
     * 296 remaining divergences sat in exactly such a branch. The tiers are read from {@link ChainStep}, not from a
     * literal beside this assertion: compared against a hand-written list, a new tier with no vector left both sides
     * unchanged and the check green.
     */
    @Test
    void everyChainStepIsExercised() {
        Set<String> exercised = new LinkedHashSet<>();
        vectorFile.get("vectors").forEach(vector -> exercised.add(vector.get("expected").get("chainStep").asText()));

        assertThat(exercised).containsExactlyInAnyOrderElementsOf(ChainStep.labels());
    }

    /**
     * Proves the comparison can fail. A conformance suite that has never been shown to reject anything is evidence of
     * nothing, which is the failure mode this codebase has hit more than once.
     */
    @Test
    void aMutatedExpectationIsRejected() {
        // Selected by id, not by index. The mutation has to land on a field this vector's own tier keys on, and a
        // vector file regenerated into a different order would otherwise silently move the test onto a tier whose
        // pre-image ignores it -- which is how the assertion below became vacuous in the first place.
        JsonNode vector = vectorById("crt-dn-public-key-target");
        JsonNode component = vector.get("component");
        CryptoAssetIdentity.Identity actual = identity
                .of(component, DocumentScope.of(documentAround(vector), normalizer), Set.of());
        String ratifiedPreImage = vector.get("expected").get("preImage").asText();

        assertThat(actual.preImage()).isEqualTo(ratifiedPreImage);

        // The mutation goes on the INPUT. Comparing the ratified pre-image against itself-plus-a-character cannot
        // fail: AssertJ has already thrown if the line above did not hold, so the old assertion was a statement about
        // string concatenation rather than about this pipeline. Perturbing the component is what proves the
        // comparison has teeth -- and the vector file carries no integrity pin of its own, so this is the only thing
        // standing between a silently edited expectation and a green run.
        ObjectNode mutated = component.deepCopy();
        ObjectNode certificate = (ObjectNode) mutated.get("cryptoProperties").get("certificateProperties");
        certificate.put("subjectName", certificate.get("subjectName").asText() + "-mutated");
        CryptoAssetIdentity.Identity fromMutatedInput = identity
                .of(mutated, DocumentScope.of(documentAround(vector), normalizer), Set.of());

        assertThat(fromMutatedInput.preImage())
                .describedAs("a perturbed component must not reproduce the ratified pre-image")
                .isNotEqualTo(ratifiedPreImage);
        assertThat(fromMutatedInput.key())
                .describedAs("and therefore must not reproduce the ratified key")
                .isNotEqualTo(actual.key());
    }

    private JsonNode vectorById(String id) {
        for (JsonNode vector : vectorFile.get("vectors")) {
            if (id.equals(vector.path("id").asText())) {
                return vector;
            }
        }
        throw new AssertionError("the ratified vector set no longer carries " + id);
    }

    /** Rebuilds the single-component document the vector describes, so its {@code refTargets} can resolve. */
    private static JsonNode documentAround(JsonNode vector) {
        ObjectMapper mapper = new ObjectMapper();
        ArrayNode components = mapper.createArrayNode();
        components.add(vector.get("component"));
        JsonNode targets = vector.get("refTargets");
        if (targets != null && targets.isArray()) {
            targets.forEach(components::add);
        }
        ObjectNode document = mapper.createObjectNode();
        document.set("components", components);
        return document;
    }
}
