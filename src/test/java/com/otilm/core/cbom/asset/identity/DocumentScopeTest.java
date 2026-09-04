package com.otilm.core.cbom.asset.identity;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.otilm.core.model.cbom.CryptoAssetIdentityGuard;
import java.util.List;
import java.util.Set;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * The document-scoped derivations: what refutes a producer-supplied identifier, what does not, and what a refutation
 * does to the key.
 *
 * <p>
 * Every ratified vector wraps one component in a document of its own, so the vector suite can never watch two
 * components contradict each other, and the extractor fixtures carried no shared digest or suite code either. Until
 * this class existed, reverting {@link DocumentScope}'s refutation to whole-tuple comparison -- the regression its own
 * Javadoc records -- or making {@link DocumentScope#refutedAcross} return nothing left every test green. Each test here
 * names the mutation it fails under.
 */
class DocumentScopeTest {

    private static final ObjectMapper MAPPER = new ObjectMapper();

    private static final AssetNormalizer NORMALIZER = new AssetNormalizer(IdentityTables.load());

    private static final CryptoAssetIdentity IDENTITY = new CryptoAssetIdentity(NORMALIZER);

    private static final String DIGEST = "ab".repeat(32);

    /** The spelling under which {@link CertificateDigests} files a SHA-256 {@code component.hashes[]} claim. */
    private static final String CLAIM = "sha-256:" + DIGEST;

    /** Serial and validity: the facts a sparse record leaves unstated. */
    private static final String RICHER_FACTS = ",\"serialNumber\":\"0A\",\"notValidBefore\":\"2026-01-01T00:00:00Z\","
            + "\"notValidAfter\":\"2027-01-01T00:00:00Z\"";

    // ---------------------------------------------------------------- certificate digests

    /**
     * A digest two certificates disagree about is unusable for both. The second certificate sits in a nested component,
     * so a contradiction buried in a sub-tree refutes too.
     */
    @Test
    void twoCertificatesContradictingEachOtherAboutOneDigestRefuteIt() {
        JsonNode document = document(certificate("alpha", "CN=alpha.example", ""),
                library(certificate("beta", "CN=beta.example", "")));

        assertThat(DocumentScope.of(document, NORMALIZER).refutedCertificateDigests()).containsExactly(CLAIM);
    }

    /**
     * Refutation needs a contradiction on a field both records state.
     *
     * <p>
     * Comparing whole tuples made a sparse record conflict with a richer one describing the same certificate, and
     * destroyed a legitimate merge. Under that mutation the two tuples here differ and this assertion fails; the
     * certificates themselves agree on everything both of them say.
     */
    @Test
    void aSparseRecordDoesNotRefuteARicherOneDescribingTheSameCertificate() {
        JsonNode document = document(certificate("sparse", "CN=alpha.example", ""),
                certificate("rich", "CN=alpha.example", RICHER_FACTS));

        assertThat(DocumentScope.of(document, NORMALIZER).refutedCertificateDigests()).isEmpty();
    }

    /**
     * A contradiction on serial or validity refutes as surely as one on subject.
     *
     * <p>
     * The renewal shape: one subject, one issuer, one claimed fingerprint stamped by the producer on both, and two
     * different certificates underneath. Every other fixture in this class differs in the <em>subject</em>, so
     * shortening {@code refute}'s field list to subject and issuer alone left them all green while this pair would have
     * merged on {@code CRT|H}.
     */
    @Test
    void aContradictionOnSerialOrValidityRefutesToo() {
        JsonNode first = certificate("renewed-2026", "CN=alpha.example",
                ",\"serialNumber\":\"0A\",\"notValidAfter\":\"2027-01-01T00:00:00Z\"");
        JsonNode second = certificate("renewed-2027", "CN=alpha.example",
                ",\"serialNumber\":\"0B\",\"notValidAfter\":\"2028-01-01T00:00:00Z\"");
        DocumentScope scope = DocumentScope.of(document(first, second), NORMALIZER);

        assertThat(scope.refutedCertificateDigests()).containsExactly(CLAIM);
        assertThat(IDENTITY.of(first, scope, Set.of()).key())
                .describedAs("so the renewal and the certificate it replaced do not merge on the shared claim")
                .isNotEqualTo(IDENTITY.of(second, scope, Set.of()).key());
    }

    /**
     * Only a protocol contributes a suite code, and the type is read folded.
     *
     * <p>
     * Every other fixture here spells {@code protocol} and {@code certificate} canonically and lowercase, so a reader
     * comparing the routed type raw -- or skipping the non-protocol check altogether -- passed them all. This document
     * states the types the way a producer does.
     */
    @Test
    void theContributingTypesAreReadFoldedAndOnlyAProtocolOffersASuite() {
        JsonNode camelCased = read(protocol("camel", "TLS_AES_128_GCM_SHA256", "\"0x1301\"")
                .toString()
                .replace("\"assetType\":\"protocol\"", "\"assetType\":\"Protocol\""));
        JsonNode otherName = read(protocol("other", "TLS_CHACHA20_POLY1305_SHA256", "\"0x1301\"")
                .toString()
                .replace("\"assetType\":\"protocol\"", "\"assetType\":\"PROTOCOL\""));

        assertThat(DocumentScope.of(document(camelCased, otherName), NORMALIZER).refutedSuiteCodes())
                .describedAs("a camel-cased and an upper-cased protocol still contradict each other")
                .containsExactly("1301");
        assertThat(DocumentScope
                .of(document(camelCased, staleSuiteBlockTyped("\"algorithm\"")), NORMALIZER)
                .refutedSuiteCodes())
                .describedAs("while an algorithm carrying a stale suites block contributes no second name")
                .isEmpty();
    }

    /**
     * The gate bars every <em>stated</em> non-protocol type, routable or not, and lets an unstated one contribute.
     *
     * <p>
     * Requiring the type to route barred only the three other known types, so {@code protocols} -- a plausible typo,
     * and exactly the shape the gate was added for -- still refuted a real code document-wide. The absent-type arm is
     * the stated adjudication that a block carrying suites and no type is more likely a protocol than not; flipping it
     * left every other test green.
     */
    @Test
    void aStatedTypeIsBarredWhetherOrNotItRoutesAndAnUnstatedOneContributes() {
        JsonNode genuine = protocol("genuine", "TLS_AES_128_GCM_SHA256", "\"0x1301\"");

        assertThat(DocumentScope
                .of(document(genuine, staleSuiteBlockTyped("\"protocols\"")), NORMALIZER)
                .refutedSuiteCodes())
                .describedAs("a stated type the router does not know is still not protocol")
                .isEmpty();
        assertThat(DocumentScope
                .of(document(genuine, staleSuiteBlockTyped("\"cryptographic-asset\"")), NORMALIZER)
                .refutedSuiteCodes()).isEmpty();
        assertThat(DocumentScope.of(document(genuine, staleSuiteBlockTyped(null)), NORMALIZER).refutedSuiteCodes())
                .describedAs("a block that states no type at all still contributes")
                .containsExactly("1301");
        assertThat(DocumentScope.of(document(genuine, staleSuiteBlockTyped("\"  \"")), NORMALIZER).refutedSuiteCodes())
                .describedAs("and a blank type is an unstated one")
                .containsExactly("1301");
    }

    /**
     * The refutation reaches the key: the digest tier is skipped, the composite answers instead, and the row records
     * why it stayed separate -- which is what the alias-repair refusal reads.
     */
    @Test
    void aRefutedDigestKeysBelowTheDigestTierAndStampsTheGuard() {
        JsonNode alpha = certificate("alpha", "CN=alpha.example", "");
        DocumentScope scope = DocumentScope.of(document(alpha, certificate("beta", "CN=beta.example", "")), NORMALIZER);

        CryptoAssetIdentity.Identity alone = IDENTITY.of(alpha);
        CryptoAssetIdentity.Identity refuted = IDENTITY.of(alpha, scope, Set.of());

        assertThat(alone.step()).isEqualTo("crt:component-hash");
        assertThat(alone.guard()).isNull();
        assertThat(refuted.step()).isEqualTo("crt:dn-composite");
        assertThat(refuted.guard()).isEqualTo(CryptoAssetIdentityGuard.REFUTED_CERTIFICATE_DIGEST);
        assertThat(refuted.key()).isNotEqualTo(alone.key());
    }

    /** A digest a batch-scoped index refuted is honoured exactly as one the document refuted, key and guard alike. */
    @Test
    void aBatchRefutationKeysExactlyAsADocumentRefutationDoes() {
        JsonNode alpha = certificate("alpha", "CN=alpha.example", "");
        DocumentScope scope = DocumentScope.of(document(alpha, certificate("beta", "CN=beta.example", "")), NORMALIZER);

        CryptoAssetIdentity.Identity byDocument = IDENTITY.of(alpha, scope, Set.of());
        CryptoAssetIdentity.Identity byBatch = IDENTITY.of(alpha, DocumentScope.none(), Set.of(CLAIM));

        assertThat(byBatch.guard()).isEqualTo(CryptoAssetIdentityGuard.REFUTED_CERTIFICATE_DIGEST);
        assertThat(byBatch.key()).isEqualTo(byDocument.key());
    }

    /**
     * The hazard no single document can see: two certificates claiming one digest in different documents. Each scope
     * alone refutes nothing; the batch view refutes the digest. A {@code refutedAcross} returning an empty set fails
     * here.
     */
    @Test
    void refutedAcrossSeesAContradictionThatNoSingleDocumentCan() {
        JsonNode first = document(certificate("alpha", "CN=alpha.example", ""));
        JsonNode second = document(certificate("beta", "CN=beta.example", ""));

        assertThat(DocumentScope.of(first, NORMALIZER).refutedCertificateDigests()).isEmpty();
        assertThat(DocumentScope.of(second, NORMALIZER).refutedCertificateDigests()).isEmpty();
        assertThat(DocumentScope.refutedAcross(List.of(first, second), NORMALIZER)).containsExactly(CLAIM);
    }

    /** The batch rule is the document rule over more documents: sparse against rich is still no contradiction. */
    @Test
    void refutedAcrossNeedsTheContradictionTheDocumentRuleNeeds() {
        JsonNode sparse = document(certificate("sparse", "CN=alpha.example", ""));
        JsonNode rich = document(certificate("rich", "CN=alpha.example", RICHER_FACTS));

        assertThat(DocumentScope.refutedAcross(List.of(sparse, rich), NORMALIZER)).isEmpty();
    }

    // ---------------------------------------------------------------- suite codes

    /**
     * A code under two suites is refuted; one suite named in two cases, or under its OpenSSL alias, is one suite.
     *
     * <p>
     * {@code TLS_AKE_WITH_AES_128_GCM_SHA256} is what one producer calls code {@code 0x1301}; IANA calls it
     * {@code TLS_AES_128_GCM_SHA256}. Comparing raw names read the pair as a contradiction, so one estate scanned by
     * two tools refuted the code document-wide and re-keyed every protocol row claiming it -- including a third
     * endpoint that carried only the IANA spelling. Refutation is the control for a placeholder stamped on genuinely
     * different suites, which is what the contradicted fixture now describes.
     */
    @Test
    void oneCodeUnderTwoSuitesIsRefutedWhileOneSuiteUnderTwoNamesIsNot() {
        JsonNode contradicted = document(protocol("one", "TLS_AES_128_GCM_SHA256", "\"0x13\",\"0x01\""),
                protocol("two", "TLS_CHACHA20_POLY1305_SHA256", "\"0x1301\""));
        JsonNode repeated = document(protocol("one", "TLS_AES_128_GCM_SHA256", "\"0x13\",\"0x01\""),
                protocol("two", "tls_aes_128_gcm_sha256", "\"0x1301\""));
        JsonNode aliased = document(protocol("one", "TLS_AES_128_GCM_SHA256", "\"0x13\",\"0x01\""),
                protocol("two", "TLS_AKE_WITH_AES_128_GCM_SHA256", "\"0x1301\""),
                protocol("three", "TLS_AES_128_GCM_SHA256", "\"0x1301\""));

        assertThat(DocumentScope.of(contradicted, NORMALIZER).refutedSuiteCodes()).containsExactly("1301");
        assertThat(DocumentScope.of(repeated, NORMALIZER).refutedSuiteCodes()).isEmpty();
        assertThat(DocumentScope.of(aliased, NORMALIZER).refutedSuiteCodes())
                .describedAs("a naming alias is not a contradiction")
                .isEmpty();
        assertThat(IDENTITY.of(aliased.get("components").get(0), DocumentScope.of(aliased, NORMALIZER), Set.of()).key())
                .describedAs("so the endpoint that never saw the alias keys as it would alone")
                .isEqualTo(IDENTITY.of(aliased.get("components").get(0)).key());
    }

    /**
     * A refuted code falls back to the suite's name, so two protocols that would have merged on a placeholder code
     * split on what they actually call the suite.
     */
    @Test
    void aRefutedSuiteCodeFallsBackToTheSuiteNameInTheKey() {
        JsonNode one = protocol("one", "TLS_AES_128_GCM_SHA256", "\"0x13\",\"0x01\"");
        JsonNode two = protocol("two", "TLS_CHACHA20_POLY1305_SHA256", "\"0x1301\"");
        DocumentScope scope = DocumentScope.of(document(one, two), NORMALIZER);

        assertThat(CipherSuites.tokens(one.get("cryptoProperties"), scope.refutedSuiteCodes()))
                .isEqualTo("n:" + PreImageSlot.of("TLS_AES_128_GCM_SHA256"));
        assertThat(IDENTITY.of(one, scope, Set.of()).key()).isNotEqualTo(IDENTITY.of(two, scope, Set.of()).key());
        assertThat(IDENTITY.of(one).key())
                .describedAs("with no document around them, both sit on the code and merge")
                .isEqualTo(IDENTITY.of(two).key());
    }

    // ---------------------------------------------------------------- helpers

    /** A certificate claiming {@link #DIGEST} through {@code component.hashes[]}, issued by one CA. */
    private static JsonNode certificate(String name, String subject, String furtherFacts) {
        return read("{\"type\":\"cryptographic-asset\",\"name\":\"" + name + "\",\"hashes\":[{\"alg\":\"SHA-256\","
                + "\"content\":\"" + DIGEST + "\"}],\"cryptoProperties\":{\"assetType\":\"certificate\","
                + "\"certificateProperties\":{\"subjectName\":\"" + subject + "\",\"issuerName\":\"CN=vector ca\""
                + furtherFacts + "}}}");
    }

    /**
     * A component carrying a protocol's suites block under the given {@code assetType} JSON, or under none when
     * {@code null} -- the shape the non-protocol gate decides about.
     */
    private static JsonNode staleSuiteBlockTyped(String assetTypeJson) {
        return read("{\"type\":\"cryptographic-asset\",\"name\":\"stale\",\"cryptoProperties\":{"
                + (assetTypeJson == null ? "" : "\"assetType\":" + assetTypeJson + ",")
                + "\"protocolProperties\":{\"cipherSuites\":[{\"name\":"
                + "\"SOMETHING_ELSE\",\"identifiers\":[\"0x1301\"]}]}}}");
    }

    /** A TLS 1.3 protocol offering one suite, so its key differs from a sibling's only through that suite's token. */
    private static JsonNode protocol(String name, String suiteName, String identifiers) {
        return read("{\"type\":\"cryptographic-asset\",\"name\":\"" + name + "\",\"cryptoProperties\":"
                + "{\"assetType\":\"protocol\",\"protocolProperties\":{\"type\":\"tls\",\"version\":\"1.3\","
                + "\"cipherSuites\":[{\"name\":\"" + suiteName + "\",\"identifiers\":[" + identifiers + "]}]}}}");
    }

    private static JsonNode library(JsonNode... children) {
        ObjectNode library = MAPPER.createObjectNode();
        library.put("type", "library");
        library.put("name", "outer");
        library.set("components", components(children));
        return library;
    }

    private static JsonNode document(JsonNode... components) {
        ObjectNode document = MAPPER.createObjectNode();
        document.set("components", components(components));
        return document;
    }

    private static ArrayNode components(JsonNode... components) {
        ArrayNode array = MAPPER.createArrayNode();
        for (JsonNode component : components) {
            array.add(component);
        }
        return array;
    }

    private static JsonNode read(String json) {
        try {
            return MAPPER.readTree(json);
        } catch (JsonProcessingException e) {
            throw new IllegalArgumentException("test fixture is not JSON", e);
        }
    }
}
