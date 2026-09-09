package com.otilm.core.cbom.asset.identity;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.core.StreamReadFeature;
import com.fasterxml.jackson.core.exc.StreamConstraintsException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.otilm.core.cbom.asset.OccurrenceEvidenceCapper;
import com.otilm.core.serialization.ObjectMapperFactory;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * The walker: what a document yields, and what no document can make it do.
 *
 * <p>
 * A CBOM is untrusted input from a third-party scanner, so most of what is asserted here is about robustness rather
 * than about extraction. The governing property is that <b>nothing a producer can write makes the walk fail</b>: one
 * malformed asset must not cost an operator the other four thousand.
 */
class CbomAssetExtractorTest {

    private static final ObjectMapper MAPPER = new ObjectMapper();

    private static final CbomAssetExtractor EXTRACTOR = new CbomAssetExtractor(
            new CryptoAssetIdentity(new AssetNormalizer(IdentityTables.load())));

    // ---------------------------------------------------------------- extraction

    /** A redaction finding survives to the extraction boundary, where core#2073 can wire it to a report. */
    @Test
    void anIngestFindingReachesTheExtractionBoundary() {
        CbomAssetExtractor.Extraction extraction = EXTRACTOR
                .extract(read("{\"components\":[{\"type\":\"cryptographic-asset\",\"name\":\"k\","
                        + "\"cryptoProperties\":{\"assetType\":\"relatedCryptoMaterial\","
                        + "\"relatedCryptoMaterialProperties\":{\"type\":\"private-key\","
                        + "\"value\":\"-----BEGIN PRIVATE KEY-----AAAA-----END PRIVATE KEY-----\"}}}]}"));

        assertThat(extraction.assets()).hasSize(1);
        assertThat(extraction.assets().get(0).findings())
                .anySatisfy(finding -> assertThat(finding).contains("producer inlined a value"));
    }

    @Test
    void nestedComponentTreesAreWalkedToTheirLeaves() {
        JsonNode document = read("{\"components\":[{\"type\":\"library\",\"name\":\"outer\",\"components\":["
                + algorithm("AES-256") + ",{\"type\":\"library\",\"name\":\"inner\",\"components\":["
                + algorithm("RSA-2048") + "]}]}]}");

        CbomAssetExtractor.Extraction extraction = EXTRACTOR.extract(document);

        assertThat(extraction.assets()).hasSize(2);
        assertThat(extraction.skips()).isEmpty();
    }

    /**
     * A component typed {@code cryptographic-asset} with no {@code cryptoProperties} is extracted, not skipped.
     *
     * <p>
     * It keys on the unroutable backstop tier with its name. There is one in the validation corpus, and skipping it
     * would lose the only record that a producer emitted something the specification cannot route.
     */
    @Test
    void aComponentWithNoCryptoPropertiesIsUnroutableRatherThanSkipped() {
        CbomAssetExtractor.Extraction extraction = EXTRACTOR
                .extract(read("{\"components\":[{\"type\":\"cryptographic-asset\",\"name\":\"broken\"}]}"));

        assertThat(extraction.skips()).isEmpty();
        assertThat(extraction.assets())
                .singleElement()
                .satisfies(asset -> assertThat(asset.chainStep()).isEqualTo("backstop:unknown-type"));
    }

    @Test
    void aComponentCarryingCryptoPropertiesIsExtractedWhateverItsDeclaredType() {
        CbomAssetExtractor.Extraction extraction = EXTRACTOR
                .extract(read("{\"components\":[{\"type\":\"library\","
                        + "\"name\":\"x\",\"cryptoProperties\":{\"assetType\":\"algorithm\"}}]}"));

        assertThat(extraction.assets()).hasSize(1);
    }

    @Test
    void componentsThatAreNotCryptographicAssetsAreIgnoredRatherThanSkipped() {
        CbomAssetExtractor.Extraction extraction = EXTRACTOR
                .extract(read("{\"components\":[{\"type\":\"library\",\"name\":\"jackson\"}]}"));

        assertThat(extraction.assets()).isEmpty();
        assertThat(extraction.skips()).describedAs("a library is not a skip; it was never a candidate").isEmpty();
    }

    // ---------------------------------------------------------------- determinism

    /**
     * An asset's identity is a function of the asset and of what its document says about it, never of where in the
     * document it sits, so permuting the document cannot change what results.
     *
     * <p>
     * This is the property the whole inventory rests on: two nodes, two releases and two re-ingests of one document
     * must agree, and the merge must not depend on which producer synced first.
     *
     * <p>
     * Five flat, self-contained components cannot test it: with no reference, no duplicated {@code bom-ref}, no shared
     * digest and no shared suite code there is no document-scoped state for order to reach, and first-in-document-order
     * reference resolution passed such a fixture. The document here carries every kind of that state -- a reference
     * from a certificate into a nested library, a duplicated ref that a certificate points at, two certificates
     * contradicting one another about one digest, two protocols disagreeing about one suite code -- and each is proven
     * live before the permutation is asserted, because a refutation that never fired would leave this test green
     * whatever the walker did with order.
     */
    @Test
    void permutingTheDocumentChangesNothingButOrder() {
        List<String> components = new ArrayList<>(List
                .of(algorithm("AES-256"), algorithm("RSA-2048"), algorithm("SHA-256"), certificate("a"),
                        certificate("b"), material("dup-first", "k", "AQID"), material("dup-second", "k", "BAUG"),
                        certificateReferencing("ambiguous", "k"), certificateReferencing("dangling", "nowhere"),
                        library("outer", algorithm("ChaCha20"), material("nested-key", "u", "AAAA")),
                        certificateReferencing("resolving", "u"), certificateWithDigest("digest-one", "one"),
                        certificateWithDigest("digest-two", "two"),
                        protocolWithSuite("tls-one", "TLS_AES_128_GCM_SHA256"),
                        protocolWithSuite("tls-two", "TLS_CHACHA20_POLY1305_SHA256"),
                        material("second-key", "v", "BBBB"), certificateReferencingKeys("two-keys", "u", "v")));
        Map<String, Row> forward = rowsByName(components);
        assertThatEveryDocumentScopedEffectIsLive(forward);

        Collections.reverse(components);
        Map<String, Row> reversed = rowsByName(components);
        Collections.shuffle(components, new java.util.Random(20260827));
        Map<String, Row> shuffled = rowsByName(components);

        assertThat(reversed).isEqualTo(forward);
        assertThat(shuffled).isEqualTo(forward);
    }

    /**
     * Order inside a component is a serialization of the document as much as the order of its components is.
     *
     * <p>
     * {@code subjectPublicKeyRef} took the first related-asset entry typed {@code public-key}, so a certificate
     * carrying two of them keyed differently depending on which was written first -- one level below the rule that a
     * duplicated {@code bom-ref} resolves to nothing. The permutation fixture shuffles components, not this array, so
     * the pair is transposed here. Two entries name nothing, exactly as the duplicated ref does.
     */
    @Test
    void transposingTwoPublicKeyEntriesChangesNothing() {
        String keys = material("first-key", "u", "AAAA") + "," + material("second-key", "v", "BBBB") + ",";
        Map<String, Row> forward = rowsByName(List
                .of(keys + certificateReferencingKeys("two-keys", "u", "v") + ","
                        + certificateReferencing("none", "nowhere")));
        Map<String, Row> transposed = rowsByName(List
                .of(keys + certificateReferencingKeys("two-keys", "v", "u") + ","
                        + certificateReferencing("none", "nowhere")));

        assertThat(transposed).containsEntry("two-keys", forward.get("two-keys"));
        assertThat(forward.get("two-keys").identityKey())
                .describedAs("an ambiguous public-key reference resolves to nothing, as a dangling one does")
                .isEqualTo(forward.get("none").identityKey());
    }

    /**
     * A permutation test proves nothing about state that never fired, so each document-scoped effect is asserted live
     * first. The referencing certificates share one subject, issuer and validity, so their keys can differ only through
     * what the reference resolved to.
     */
    private static void assertThatEveryDocumentScopedEffectIsLive(Map<String, Row> rows) {
        assertThat(rows).hasSize(18);
        assertThat(rows.get("resolving").identityKey())
                .describedAs("the reference into the nested library resolved and filled the composite's key slot")
                .isNotEqualTo(rows.get("dangling").identityKey());
        assertThat(rows.get("ambiguous").identityKey())
                .describedAs("a duplicated ref resolves to nothing, exactly as a dangling one does")
                .isEqualTo(rows.get("dangling").identityKey());
        assertThat(rows.get("two-keys").identityKey())
                .describedAs("and so do two public-key entries on one certificate")
                .isEqualTo(rows.get("dangling").identityKey());
        assertThat(List.of(rows.get("digest-one").chainStep(), rows.get("digest-two").chainStep()))
                .describedAs("the contradicted digest was refused and both certificates fell to the composite")
                .containsOnly("crt:dn-composite");
        assertThat(rows.get("tls-one").identityKey())
                .describedAs("the refuted suite code fell back to two different suite names")
                .isNotEqualTo(rows.get("tls-two").identityKey());
    }

    /**
     * The object-shaped {@code value} arm of the composite's key slot, which no ratified vector reaches.
     *
     * <p>
     * {@code asText()} on a container yields the empty string rather than null, so every certificate pointing at a
     * target whose {@code sha256} was an object or an array used to render the bare discriminator {@code K:} -- and a
     * JSON null rendered {@code K:null}, a boolean {@code K:true}. Read as the absent claim it is instead, which is the
     * same reading a blank fingerprint content already gets. Note what that does and does not buy: it stops a malformed
     * digest impersonating a real one, but two certificates pointing at two different KEYLESS material targets still
     * share an empty slot, because the fallback below discriminates an algorithm target only. That over-merge is the
     * first of the open findings on core#2165, not something this closes.
     */
    @Test
    void aMalformedKeyDigestReadsAsTheAbsentClaimItIs() {
        Map<String, Row> rows = rowsByName(List
                .of(certificateReferencing("cert-upper", "k-upper"), certificateReferencing("cert-lower", "k-lower"),
                        certificateReferencing("cert-other", "k-other"),
                        certificateReferencing("cert-container", "k-container"),
                        certificateReferencing("cert-json-null", "k-json-null"),
                        certificateReferencing("cert-keyless", "k-keyless"),
                        publicKeyWithValue("k-upper", "{\"sha256\":\"" + "AB".repeat(32) + "\"}"),
                        publicKeyWithValue("k-lower", "{\"sha256\":\"" + "ab".repeat(32) + "\"}"),
                        publicKeyWithValue("k-other", "{\"sha256\":\"" + "cd".repeat(32) + "\"}"),
                        publicKeyWithValue("k-container", "{\"sha256\":{}}"),
                        publicKeyWithValue("k-json-null", "{\"sha256\":null}"), publicKeyWithValue("k-keyless", null)));

        assertThat(rows.get("cert-upper").identityKey())
                .describedAs("one digest spelled two ways is one key: the textual arm renders lowercase hex, so an "
                        + "uppercase spelling keyed apart from it until the fold")
                .isEqualTo(rows.get("cert-lower").identityKey());
        assertThat(rows.get("cert-other").identityKey())
                .describedAs("two different digests still discriminate, so the fold above is not vacuous")
                .isNotEqualTo(rows.get("cert-lower").identityKey());
        assertThat(rows.get("cert-container").identityKey())
                .describedAs("a container sha256 is no digest, so it must not render a discriminator a real digest "
                        + "could never produce")
                .isEqualTo(rows.get("cert-keyless").identityKey());
        assertThat(rows.get("cert-json-null").identityKey())
                .describedAs("a JSON null keyed as the literal text `null` before this")
                .isEqualTo(rows.get("cert-keyless").identityKey());
        assertThat(rows.get("cert-container").identityKey())
                .describedAs("a malformed digest must not impersonate a real one")
                .isNotEqualTo(rows.get("cert-lower").identityKey());
    }

    @Test
    void reExtractingTheSameDocumentYieldsTheSameKeys() {
        JsonNode document = read("{\"components\":[" + algorithm("AES-256-GCM") + "," + certificate("x") + "]}");

        assertThat(keysOf(EXTRACTOR.extract(document))).isEqualTo(keysOf(EXTRACTOR.extract(document)));
    }

    // ---------------------------------------------------------------- wild input

    /**
     * Every shape here is schema-valid or near enough that a real producer has emitted it, and none may fail the run.
     *
     * <p>
     * The version number is the sharpest: one producer ships {@code specVersion} as the number {@code 999}. Nothing in
     * this walker reads it, which is why that costs nothing -- the 1.6 and 1.7 differences are field renames absorbed
     * by the normalizer reading both spellings.
     */
    @ParameterizedTest
    @ValueSource(strings = {
            "{\"specVersion\":999,\"components\":[{\"type\":\"cryptographic-asset\",\"name\":\"a\",\"cryptoProperties\":{\"assetType\":\"algorithm\"}}]}",
            "{\"specVersion\":\"1.6\",\"components\":[{\"type\":\"cryptographic-asset\",\"name\":\"a\",\"cryptoProperties\":{\"assetType\":\"algorithm\",\"algorithmProperties\":{\"nistQuantumSecurityLevel\":\"not-a-number\"}}}]}",
            "{\"components\":[{\"type\":\"cryptographic-asset\",\"name\":\"a\",\"cryptoProperties\":{\"assetType\":\"algorithm\"},\"evidence\":{}}]}",
            "{\"components\":[{\"type\":\"cryptographic-asset\",\"name\":\"a\",\"cryptoProperties\":{\"assetType\":\"algorithm\"},\"nonstandardField\":{\"deeply\":[1,2,3]}}]}",
            "{\"components\":[{\"type\":\"cryptographic-asset\",\"cryptoProperties\":{\"assetType\":\"algorithm\"}}]}",
            "{\"components\":[{\"type\":\"cryptographic-asset\",\"name\":null,\"cryptoProperties\":{\"assetType\":null}}]}",
            "{\"components\":[{\"type\":\"cryptographic-asset\",\"name\":\"a\",\"cryptoProperties\":{\"assetType\":\"protocol\",\"protocolProperties\":{\"type\":\"tls\",\"version\":\"n/a\",\"cipherSuites\":[{}]}}}]}"})
    void wildButLegalInputParsesWithoutFailingTheRun(String json) {
        CbomAssetExtractor.Extraction extraction = EXTRACTOR.extract(read(json));

        assertThat(extraction.skips()).isEmpty();
        assertThat(extraction.assets()).hasSize(1);
        assertThat(extraction.assets().get(0).identityKey()).hasSize(64);
    }

    @ParameterizedTest
    @ValueSource(strings = {
            "{}",
            "{\"components\":[]}",
            "{\"components\":\"not-an-array\"}",
            "{\"components\":[null,1,\"two\"]}"})
    void aDocumentWithNothingToExtractYieldsNothing(String json) {
        CbomAssetExtractor.Extraction extraction = EXTRACTOR.extract(read(json));

        assertThat(extraction.assets()).isEmpty();
        assertThat(extraction.skips()).isEmpty();
    }

    /**
     * A caller passing no batch index passes {@code null} as easily as an empty set, and {@code null} used to reach
     * {@code addAll} inside the certificate tier -- so every certificate in the document became a silent skip while
     * every other asset type extracted.
     */
    @Test
    void aNullBatchIsAnEmptyBatch() {
        JsonNode document = read("{\"components\":[{\"type\":\"cryptographic-asset\",\"name\":\"cert\","
                + "\"cryptoProperties\":{\"assetType\":\"certificate\",\"certificateProperties\":"
                + "{\"subjectName\":\"CN=a\",\"issuerName\":\"CN=ca\"}}}]}");

        CbomAssetExtractor.Extraction extraction = EXTRACTOR.extract(document, null);

        assertThat(extraction.skips()).isEmpty();
        assertThat(extraction.assets()).hasSize(1);
        assertThat(extraction.documentScopeUnavailable()).isFalse();
    }

    @Test
    void anAbsentDocumentIsNotAFailure() {
        assertThat(EXTRACTOR.extract(null).assets()).isEmpty();
        assertThat(EXTRACTOR.extract(read("[]")).assets()).isEmpty();
    }

    /**
     * A document nested deeply enough to be dangerous is refused by the parser, before the walker is reached.
     *
     * <p>
     * This is the bound that actually protects the ingest, and it is not the walker's: Jackson refuses past 1000 levels
     * by default. The walker's own bound is set to match it, so that nothing which <em>parses</em> is ever truncated --
     * an earlier bound of 64 would have silently discarded every component below it in a document the parser had
     * accepted, which is data loss wearing robustness as a disguise.
     */
    @Test
    void aPathologicallyNestedDocumentIsRefusedByTheParser() {
        assertThatThrownBy(() -> read(nestedDocument(1200)))
                .describedAs("the parser is the real bound; the walker never sees such a document")
                .hasRootCauseInstanceOf(StreamConstraintsException.class);
    }

    /**
     * A document nested deeply but legally is walked to the bottom, with nothing dropped.
     *
     * <p>
     * The companion to the case above, and the one that would have caught the bound being set too low: this depth
     * parses, so every asset in it must come out.
     *
     * <p>
     * Note the units differ, which is why the walker's bound can never bite. One component level costs <em>two</em>
     * JSON nesting levels -- the object and its {@code components} array -- so the parser's 1000-level limit admits
     * roughly 499 component levels, against the walker's bound of 1000. The fixture is sized in component levels.
     */
    @Test
    void aDeeplyButLegallyNestedDocumentLosesNothing() {
        CbomAssetExtractor.Extraction extraction = EXTRACTOR.extract(read(nestedDocument(400)));

        assertThat(extraction.assets()).describedAs("the asset at the bottom must still be found").hasSize(1);
        assertThat(extraction.depthLimitReached()).isFalse();
        assertThat(extraction.skips()).isEmpty();
    }

    /**
     * A skip names the component and the failure class, never the payload.
     *
     * <p>
     * A document is untrusted input. A skip that quoted what it could not parse would be a disclosure channel for
     * exactly the documents least worth trusting, and it would sit outside everything the redaction proof covers.
     */
    @Test
    void aSkipNamesTheComponentAndNeverThePayload() {
        String secret = "s3cr3t-material-value";
        JsonNode document = read("{\"components\":[{\"type\":\"cryptographic-asset\",\"name\":\"leaky\","
                + "\"cryptoProperties\":{\"assetType\":\"related-crypto-material\","
                + "\"relatedCryptoMaterialProperties\":{\"type\":\"private-key\",\"value\":\"" + secret + "\"}}}]}");

        CbomAssetExtractor.Extraction extraction = EXTRACTOR.extract(document);

        assertThat(extraction.assets()).hasSize(1);
        assertThat(extraction.toString()).doesNotContain(secret);
        assertThat(extraction.skips()).allSatisfy(skip -> assertThat(skip.reason()).doesNotContain(secret));
    }

    /**
     * One unkeyable component costs its own row and nothing else.
     *
     * <p>
     * This is the class's headline guarantee -- a producer's malformed asset must not cost an operator the other four
     * thousand -- and until this test existed nothing in the suite ever produced a non-empty skip list, so the broad
     * {@code catch (RuntimeException)} it rests on was never executed. A lone surrogate is the cheapest trigger: the
     * identity digest refuses one rather than letting the encoder fold it onto {@code ?}. It goes in the material
     * value, which is the field the digest actually reads -- a surrogate in the component name would sit outside this
     * tier's pre-image and key perfectly well.
     */
    @Test
    void oneUnkeyableComponentIsSkippedAndTheRestSurvive() {
        String secret = "s3cr3t-material-value";
        JsonNode document = read("{\"components\":[" + "{\"type\":\"cryptographic-asset\",\"name\":\"good-one\","
                + "\"cryptoProperties\":{\"assetType\":\"algorithm\",\"algorithmProperties\":"
                + "{\"primitive\":\"block-cipher\"}}}," + "{\"type\":\"cryptographic-asset\",\"name\":\"broken\","
                + "\"cryptoProperties\":{\"assetType\":\"related-crypto-material\","
                + "\"relatedCryptoMaterialProperties\":{\"type\":\"private-key\",\"value\":\"" + secret
                + "\\ud800\"}}}," + "{\"type\":\"cryptographic-asset\",\"name\":\"good-two\","
                + "\"cryptoProperties\":{\"assetType\":\"algorithm\",\"algorithmProperties\":"
                + "{\"primitive\":\"hash\"}}}]}");

        CbomAssetExtractor.Extraction extraction = EXTRACTOR.extract(document);

        assertThat(extraction.skips())
                .describedAs("exactly the malformed component is skipped")
                .singleElement()
                .satisfies(skip -> assertThat(skip.componentName()).isEqualTo("broken"));
        assertThat(extraction.assets())
                .describedAs("the other two are keyed regardless")
                .extracting(CbomAssetExtractor.ExtractedAsset::componentName)
                .containsExactly("good-one", "good-two");
        assertThat(extraction.skips().getFirst().reason())
                .describedAs("the failure class only -- never the payload, and never the exception's own message")
                .isEqualTo("IllegalArgumentException")
                .doesNotContain(secret);
    }

    /**
     * A location long enough to be capped must not be cut through a surrogate pair.
     *
     * <p>
     * The cap counts UTF-16 units, so a path ending in an astral character used to leave a lone high surrogate behind
     * -- well-formed producer input made malformed by the platform, which the identity digest then refused, so the
     * asset vanished with nothing an operator could act on.
     */
    @Test
    void anAstralCharacterAtTheLocationCapDoesNotCostTheAsset() {
        String location = "file:///" + "a".repeat(1_020) + "\uD83D\uDD11/key.pem";
        JsonNode document = read("{\"components\":[{\"type\":\"cryptographic-asset\",\"name\":\"TLSv1.2\","
                + "\"cryptoProperties\":{\"assetType\":\"protocol\",\"protocolProperties\":{\"type\":\"tls\"}},"
                + "\"evidence\":{\"occurrences\":[{\"location\":\"" + location + "\"}]}}]}");

        CbomAssetExtractor.Extraction extraction = EXTRACTOR.extract(document);

        assertThat(extraction.skips()).isEmpty();
        assertThat(extraction.assets()).hasSize(1);
    }

    /**
     * A string with no UTF-8 encoding in a stored surface is a reported skip, whichever tier keyed the row.
     *
     * <p>
     * {@code IdentityDigests.sha256Hex} refuses an unpaired surrogate in a pre-image, so a suite name carrying one was
     * a skip while the suite digest ran for every protocol row. Once the digest ran only on the versioned tier, a
     * version-less row keyed on {@code prt:type+name} and its retained payload carried a string the {@code jsonb}
     * evidence column cannot encode -- the failure that once rolled back a whole source upsert. The same was true all
     * along for a member no tier reads at all, such as an extension in {@code algorithmProperties} on a row keyed by
     * family. The rule is now stated at the extraction boundary, over what persistence receives.
     */
    @ParameterizedTest
    @ValueSource(strings = {
            "{\"type\":\"cryptographic-asset\",\"name\":\"ep\",\"cryptoProperties\":{\"assetType\":\"protocol\","
                    + "\"protocolProperties\":{\"type\":\"tls\",\"cipherSuites\":[{\"name\":\"TLS_BAD\\ud800\"}]}}}",
            "{\"type\":\"cryptographic-asset\",\"name\":\"alg\",\"cryptoProperties\":{\"assetType\":\"algorithm\","
                    + "\"algorithmProperties\":{\"primitive\":\"hash\",\"vendorNote\":\"x\\ud800\"}}}",
            // The name sits outside this tier's pre-image -- the value-hash tier reads the material alone -- so only
            // the boundary check can refuse it. On a family-less algorithm the name reached the pre-image and the
            // digest refused it first, which pinned nothing here.
            "{\"type\":\"cryptographic-asset\",\"name\":\"bad\\udc00name\",\"cryptoProperties\":"
                    + "{\"assetType\":\"related-crypto-material\",\"relatedCryptoMaterialProperties\":"
                    + "{\"type\":\"private-key\",\"value\":\"AAAAAAAA\"}}}",
            // The findings echo a producer member name the redaction dropped. On the value-hash tier no pre-image
            // reads that member, and the stored payload no longer carries it, so the findings are the only surface
            // it reaches.
            "{\"type\":\"cryptographic-asset\",\"name\":\"k\",\"cryptoProperties\":"
                    + "{\"assetType\":\"related-crypto-material\",\"relatedCryptoMaterialProperties\":"
                    + "{\"type\":\"private-key\",\"value\":\"AAAAAAAA\",\"bad\\ud800\":\"x\"}}}",
            // The second route into the findings, which works on every tier: the reference array is stripped from
            // every pre-image and its dropped member names are echoed.
            "{\"type\":\"cryptographic-asset\",\"name\":\"k\",\"cryptoProperties\":"
                    + "{\"assetType\":\"related-crypto-material\",\"relatedCryptoMaterialProperties\":"
                    + "{\"type\":\"private-key\",\"relatedCryptographicAssets\":[{\"ref\":\"u\",\"pem\\ud800\":\"x\"}]}}}"})
    void anUnencodableStoredStringIsASkipWhateverTierKeyedTheRow(String component) {
        CbomAssetExtractor.Extraction extraction = EXTRACTOR.extract(read("{\"components\":[" + component + "]}"));

        assertThat(extraction.assets()).isEmpty();
        assertThat(extraction.skips())
                .singleElement()
                .satisfies(skip -> assertThat(skip.reason()).isEqualTo("IllegalArgumentException"));
    }

    /**
     * Every fixture above must key on {@code origin/main}'s rule too, or it pins the boundary check for nothing: a
     * component whose surrogate a pre-image already refused was a skip before the check existed. The surrogate-free
     * spelling of each keys, which is what says the surrogate alone -- not the shape -- costs the row.
     */
    @Test
    void theUnencodableFixturesAreKeyableWithoutTheirSurrogate() {
        String[] fixtures = {
                "{\"type\":\"cryptographic-asset\",\"name\":\"badname\",\"cryptoProperties\":"
                        + "{\"assetType\":\"related-crypto-material\",\"relatedCryptoMaterialProperties\":"
                        + "{\"type\":\"private-key\",\"value\":\"AAAAAAAA\"}}}",
                "{\"type\":\"cryptographic-asset\",\"name\":\"k\",\"cryptoProperties\":"
                        + "{\"assetType\":\"related-crypto-material\",\"relatedCryptoMaterialProperties\":"
                        + "{\"type\":\"private-key\",\"value\":\"AAAAAAAA\",\"bad\":\"x\"}}}",
                "{\"type\":\"cryptographic-asset\",\"name\":\"k\",\"cryptoProperties\":"
                        + "{\"assetType\":\"related-crypto-material\",\"relatedCryptoMaterialProperties\":"
                        + "{\"type\":\"private-key\",\"relatedCryptographicAssets\":[{\"ref\":\"u\",\"pem\":\"x\"}]}}}"};
        for (String fixture : fixtures) {
            CbomAssetExtractor.Extraction extraction = EXTRACTOR.extract(read("{\"components\":[" + fixture + "]}"));
            assertThat(extraction.skips()).describedAs(fixture).isEmpty();
            assertThat(extraction.assets()).describedAs(fixture).hasSize(1);
        }
    }

    // ---------------------------------------------------------------- printed forms

    /**
     * The hand-written {@code toString} overrides are load-bearing, so what they omit is asserted.
     *
     * <p>
     * A record prints every component, and anything that logs an extraction -- or a collection holding one -- prints
     * the records inside it. The logging fence judges call sites by the words on the line, so a record printed through
     * {@code {}} carries its components past the fence with nothing for a regex to see. Deleting the override left
     * every fence test green and put the stored value in the generated printout; the only test touching a printed form
     * asserted that the <em>material secret</em> was absent, which the default printout also satisfies. The positive
     * assertion is there so a printout of nothing cannot pass.
     */
    @Test
    void aPrintedExtractionNamesTheComponentAndNeverTheStoredValue() {
        CbomAssetExtractor.Extraction extraction = EXTRACTOR
                .extract(read("{\"components\":[" + algorithm("RSA-2048") + "]}"));
        CbomAssetExtractor.ExtractedAsset asset = extraction.assets().get(0);

        assertThat(asset.toString())
                .contains("RSA-2048")
                .contains(asset.chainStep())
                .doesNotContain(asset.identityKey());
        assertThat(extraction.toString())
                .describedAs("the outer record recurses into the inner one")
                .contains("RSA-2048")
                .doesNotContain(asset.identityKey());
    }

    // ---------------------------------------------------------------- refused locations

    /**
     * An occurrence whose stated location renders as no location is recorded; one that stated none is not.
     *
     * <p>
     * Every mechanism that renders a stated location as the empty string keys onto the row an absent location keys,
     * {@code #7#3} in the triple, and through the real extractor every input here does. The key cannot separate them,
     * because this slot is unescaped and any sentinel a producer can also spell; the finding is what does. The stated
     * inputs each record exactly one line naming the occurrence and never the location, which is the string that may
     * hold the credential the sanitizer removed. The absent class -- member absent, JSON null, blank -- records
     * nothing, because blank is absent in every slot of the chain, and line breaks are whitespace to it.
     *
     * <p>
     * The keys are asserted equal on purpose: the reference operation is untouched by the recording, and a future
     * sentinel that split them would re-key every occurrence row and diverge from the kernel.
     */
    @Test
    void aStatedLocationThatRendersAsNothingIsRecordedWhereAnAbsentOneIsNot() {
        CbomAssetExtractor.ExtractedAsset absent = occurrenceRow(null);
        assertThat(absent.chainStep()).isEqualTo("prt:type+occurrence");
        assertThat(absent.findings()).isEmpty();
        assertThat(occurrenceRow("\"/a/b.java\"").identityKey())
                .describedAs("a real location keys apart, so the equalities below are not vacuous")
                .isNotEqualTo(absent.identityKey());

        List<String> statedNothing = List.of("null", "\"   \"", "\"\\u00a0\\u00a0\"", "\"\\r\\n\"");
        for (String location : statedNothing) {
            CbomAssetExtractor.ExtractedAsset row = occurrenceRow(location);
            assertThat(row.identityKey()).describedAs(location).isEqualTo(absent.identityKey());
            assertThat(row.findings()).describedAs("%s is absent, not refused", location).isEmpty();
        }

        List<String> statedAndEmptied = List
                .of("42", "true", "{}", "[]", "\"?sig=abc\"", "\"?X-Amz-Signature=\"", "\"#?tok=1\"", "\"#\"", "\"##\"",
                        "\"\\ud800\"", "\"\\ud800 ?a\"", "\"#" + " ".repeat(1030) + "a\"",
                        "\"" + "a".repeat(64 * 1024 + 1) + "\"", "\"//u:p@" + "/u:p@".repeat(39) + "host\"");
        for (String location : statedAndEmptied) {
            CbomAssetExtractor.ExtractedAsset row = occurrenceRow(location);
            assertThat(row.identityKey()).describedAs(location).isEqualTo(absent.identityKey());
            assertThat(row.evidence().get(0)).describedAs(location).containsEntry("location", "");
            assertThat(row.findings())
                    .describedAs(location)
                    .singleElement()
                    .asString()
                    .startsWith("occurrence 0: the stated location ")
                    .doesNotContain("sig")
                    .doesNotContain("tok")
                    .doesNotContain("u:p@");
        }
    }

    /** A protocol row that reaches the occurrence tier, at one occurrence whose location is the given JSON value. */
    private static CbomAssetExtractor.ExtractedAsset occurrenceRow(String locationJson) {
        String location = locationJson == null ? "" : "\"location\":" + locationJson + ",";
        CbomAssetExtractor.Extraction extraction = EXTRACTOR
                .extract(read("{\"components\":[{\"type\":\"cryptographic-asset\",\"cryptoProperties\":"
                        + "{\"assetType\":\"protocol\",\"protocolProperties\":{\"type\":\"tls\",\"cipherSuites\":[{}]}},"
                        + "\"evidence\":{\"occurrences\":[{" + location + "\"line\":7,\"offset\":3}]}}]}"));
        assertThat(extraction.skips()).isEmpty();
        return extraction.assets().get(0);
    }

    /** The occurrence location keeps its own rule: a surrogate there is scrubbed, and the asset survives. */
    @Test
    void aSurrogateInALocationIsScrubbedRatherThanCostingTheAsset() {
        CbomAssetExtractor.Extraction extraction = EXTRACTOR
                .extract(read("{\"components\":[{\"type\":\"cryptographic-asset\",\"name\":\"TLSv1.2\","
                        + "\"cryptoProperties\":{\"assetType\":\"protocol\",\"protocolProperties\":{\"type\":\"tls\"}},"
                        + "\"evidence\":{\"occurrences\":[{\"location\":\"file:///a\\ud800b/key.pem\"}]}}]}"));

        assertThat(extraction.skips()).isEmpty();
        assertThat(extraction.assets())
                .singleElement()
                .satisfies(
                        asset -> assertThat(asset.evidence().get(0)).containsEntry("location", "file:///ab/key.pem"));
    }

    /**
     * An unreadable side field costs its own slot, never the row.
     *
     * <p>
     * Jackson parses {@code 1e400} into a double of infinity, and {@code decimalValue()} on it threw a
     * {@code NumberFormatException} the extractor caught as a whole-component skip. The vector suite is blind to the
     * guard because the guard moves no key, so its consequence -- the row -- is pinned here.
     */
    @Test
    void aNonFiniteParameterSetCostsItsSlotAndNotTheRow() {
        CbomAssetExtractor.Extraction extraction = EXTRACTOR
                .extract(read("{\"components\":[{\"type\":\"cryptographic-asset\",\"name\":\"RSA\","
                        + "\"cryptoProperties\":{\"assetType\":\"algorithm\",\"algorithmProperties\":"
                        + "{\"parameterSetIdentifier\":1e400}}}]}"));

        assertThat(extraction.skips()).isEmpty();
        assertThat(extraction.assets())
                .singleElement()
                .satisfies(asset -> assertThat(asset.normalized().notes())
                        .contains(AssetNormalizer.NON_FINITE_PARAMETER_SET_NOTE));
    }

    // ---------------------------------------------------------------- the ingest mapper

    /**
     * The ingest mapper must not carry source text into a parse-failure message.
     *
     * <p>
     * With {@code INCLUDE_SOURCE_IN_LOCATION} enabled, a {@link com.fasterxml.jackson.core.JsonParseException} quotes
     * hundreds of characters of the document around the failure. A single {@code log.warn(message, exception)} on a
     * malformed document then prints raw, <em>pre-redaction</em> content into an appender -- key material included --
     * which is a channel the redaction proof does not cover, because redaction never ran.
     *
     * <p>
     * Jackson disables it by default. This asserts it rather than relying on that, because the default is a library's
     * choice and a library upgrade is exactly the kind of change nobody reads a CBOM parser for.
     */
    @Test
    void theIngestMapperKeepsSourceTextOutOfParseFailures() {
        assertThat(ObjectMapperFactory
                .storage()
                .getFactory()
                .isEnabled(StreamReadFeature.INCLUDE_SOURCE_IN_LOCATION.mappedFeature()))
                .describedAs("a parse failure must not quote the document it failed on")
                .isFalse();
    }

    @Test
    void aParseFailureMessageCarriesNoDocumentContent() {
        String secret = "s3cr3t-material-value";
        String malformed = "{\"components\":[{\"value\":\"" + secret + "\",}]}";

        assertThatParsingFails(malformed, secret);
    }

    // ---------------------------------------------------------------- helpers

    private static void assertThatParsingFails(String malformed, String secret) {
        assertThatThrownBy(() -> ObjectMapperFactory.storage().readTree(malformed))
                .describedAs("the fixture must be malformed, and its parse failure must not quote the document")
                .isInstanceOf(JsonProcessingException.class)
                .hasMessageNotContaining(secret);
    }

    private static List<String> keysOf(CbomAssetExtractor.Extraction extraction) {
        return extraction.assets().stream().map(CbomAssetExtractor.ExtractedAsset::identityKey).sorted().toList();
    }

    /** What a permutation may not move: which step keyed a component, and what it was keyed as. */
    private record Row(String chainStep, String identityKey) {
    }

    private static Map<String, Row> rowsByName(List<String> components) {
        CbomAssetExtractor.Extraction extraction = EXTRACTOR
                .extract(read("{\"components\":[" + String.join(",", components) + "]}"));
        assertThat(extraction.skips()).isEmpty();
        Map<String, Row> rows = new HashMap<>();
        for (CbomAssetExtractor.ExtractedAsset asset : extraction.assets()) {
            assertThat(rows.put(asset.componentName(), new Row(asset.chainStep(), asset.identityKey())))
                    .describedAs("component names in the fixture are unique")
                    .isNull();
        }
        return rows;
    }

    /** A component tree {@code depth} levels deep with one algorithm asset at the bottom. */
    private static String nestedDocument(int depth) {
        StringBuilder nested = new StringBuilder("{\"components\":[");
        for (int level = 0; level < depth; level++) {
            nested.append("{\"type\":\"library\",\"name\":\"n").append(level).append("\",\"components\":[");
        }
        nested.append(algorithm("AES-256")).append("]}".repeat(depth)).append("]}");
        return nested.toString();
    }

    private static String algorithm(String name) {
        return "{\"type\":\"cryptographic-asset\",\"name\":\"" + name + "\",\"cryptoProperties\":"
                + "{\"assetType\":\"algorithm\",\"algorithmProperties\":{}}}";
    }

    private static String certificate(String subject) {
        return "{\"type\":\"cryptographic-asset\",\"name\":\"cert-" + subject + "\",\"cryptoProperties\":"
                + "{\"assetType\":\"certificate\",\"certificateProperties\":{\"subjectName\":\"CN=" + subject
                + "\",\"issuerName\":\"CN=ca\"}}}";
    }

    /** A certificate whose composite can differ from its siblings' only through what its key reference resolves to. */
    private static String certificateReferencing(String name, String ref) {
        return "{\"type\":\"cryptographic-asset\",\"name\":\"" + name + "\",\"cryptoProperties\":"
                + "{\"assetType\":\"certificate\",\"certificateProperties\":{\"subjectName\":\"CN=referrer\","
                + "\"issuerName\":\"CN=ca\",\"subjectPublicKeyRef\":\"" + ref + "\"}}}";
    }

    /** The 1.7 shape of {@link #certificateReferencing}: every ref given is a {@code public-key} related asset. */
    private static String certificateReferencingKeys(String name, String... refs) {
        List<String> entries = new ArrayList<>();
        for (String ref : refs) {
            entries.add("{\"ref\":\"" + ref + "\",\"type\":\"public-key\"}");
        }
        return "{\"type\":\"cryptographic-asset\",\"name\":\"" + name + "\",\"cryptoProperties\":"
                + "{\"assetType\":\"certificate\",\"certificateProperties\":{\"subjectName\":\"CN=referrer\","
                + "\"issuerName\":\"CN=ca\",\"relatedCryptographicAssets\":[" + String.join(",", entries) + "]}}}";
    }

    /** A certificate claiming one shared digest through {@code component.hashes[]}. */
    private static String certificateWithDigest(String name, String subject) {
        return "{\"type\":\"cryptographic-asset\",\"name\":\"" + name + "\",\"hashes\":[{\"alg\":\"SHA-256\","
                + "\"content\":\"" + "cd".repeat(32) + "\"}],\"cryptoProperties\":{\"assetType\":\"certificate\","
                + "\"certificateProperties\":{\"subjectName\":\"CN=" + subject + "\",\"issuerName\":\"CN=ca\"}}}";
    }

    /**
     * A public-key material whose {@code value} is a raw JSON fragment rather than a PEM string, or absent when
     * {@code value} is null. The certificate tier reads this node directly, so the shape reaches it even though
     * {@link MaterialRedaction} drops a non-string value from the material's own row.
     */
    private static String publicKeyWithValue(String ref, String value) {
        return "{\"type\":\"cryptographic-asset\",\"bom-ref\":\"" + ref + "\",\"name\":\"" + ref + "\","
                + "\"cryptoProperties\":{\"assetType\":\"related-crypto-material\","
                + "\"relatedCryptoMaterialProperties\":{\"type\":\"public-key\""
                + (value == null ? "" : ",\"value\":" + value) + "}}}";
    }

    private static String material(String name, String ref, String value) {
        return "{\"type\":\"cryptographic-asset\",\"bom-ref\":\"" + ref + "\",\"name\":\"" + name + "\","
                + "\"cryptoProperties\":{\"assetType\":\"related-crypto-material\","
                + "\"relatedCryptoMaterialProperties\":{\"type\":\"public-key\",\"value\":\"" + value + "\"}}}";
    }

    /** A TLS 1.3 protocol offering one suite under code {@code 0x1301}, named as the caller says. */
    private static String protocolWithSuite(String name, String suiteName) {
        return "{\"type\":\"cryptographic-asset\",\"name\":\"" + name + "\",\"cryptoProperties\":"
                + "{\"assetType\":\"protocol\",\"protocolProperties\":{\"type\":\"tls\",\"version\":\"1.3\","
                + "\"cipherSuites\":[{\"name\":\"" + suiteName + "\",\"identifiers\":[\"0x13\",\"0x01\"]}]}}}";
    }

    private static String library(String name, String... children) {
        return "{\"type\":\"library\",\"name\":\"" + name + "\",\"components\":[" + String.join(",", children) + "]}";
    }

    private static JsonNode read(String json) {
        try {
            return MAPPER.readTree(json);
        } catch (JsonProcessingException e) {
            throw new IllegalArgumentException("test fixture is not JSON", e);
        }
    }

    // ---------------------------------------------------------------- evidence

    /**
     * A credential in an occurrence location must not survive into stored evidence.
     *
     * <p>
     * The keying path already strips it, or a password would be hashed into the identity. The stored evidence is the
     * other half of the same rule and had no such step: capped and retained verbatim, the evidence column would hold
     * the credential the key was careful not to hash -- in a column the read surface serves back. This test fails
     * against the version of this walker that captured no evidence, and against any that captures it unsanitized.
     */
    @Test
    void aCredentialInALocationNeverReachesStoredEvidence() {
        JsonNode document = read("{\"components\":[{\"type\":\"cryptographic-asset\",\"name\":\"k\","
                + "\"cryptoProperties\":{\"assetType\":\"algorithm\"},"
                + "\"evidence\":{\"occurrences\":[{\"location\":\"tcp://user:hunter2@host:443/p?token=abc\","
                + "\"line\":7}]}}]}");

        CbomAssetExtractor.ExtractedAsset asset = EXTRACTOR.extract(document).assets().get(0);

        assertThat(asset.evidence()).hasSize(1);
        assertThat(asset.evidence().toString()).doesNotContain("hunter2").doesNotContain("token=abc");
        assertThat(asset.evidence().get(0)).containsEntry("location", "tcp://host:443/p").containsEntry("line", 7);
    }

    /**
     * The retained list is capped and the reported count is the pre-cap total, so the gap is the record that capping
     * happened. No separate flag is needed, and none can drift out of step with the array.
     */
    @Test
    void theCountIsThePreCapTotalWhileTheListIsBounded() {
        StringBuilder occurrences = new StringBuilder();
        int reported = OccurrenceEvidenceCapper.MAX_OCCURRENCES + 25;
        for (int index = 0; index < reported; index++) {
            occurrences.append(index > 0 ? "," : "").append("{\"location\":\"file").append(index).append(".java\"}");
        }
        JsonNode document = read("{\"components\":[{\"type\":\"cryptographic-asset\",\"name\":\"k\","
                + "\"cryptoProperties\":{\"assetType\":\"algorithm\"}," + "\"evidence\":{\"occurrences\":["
                + occurrences + "]}}]}");

        CbomAssetExtractor.ExtractedAsset asset = EXTRACTOR.extract(document).assets().get(0);

        assertThat(asset.reportedOccurrences()).isEqualTo(reported);
        assertThat(asset.evidence()).hasSize(OccurrenceEvidenceCapper.MAX_OCCURRENCES);
    }

    /**
     * No evidence reported is distinct from evidence that capping emptied, so it stays {@code null} rather than
     * becoming an empty list.
     */
    @Test
    void aSourceThatReportedNoEvidenceIsDistinctFromOneThatWasCapped() {
        CbomAssetExtractor.ExtractedAsset asset = EXTRACTOR
                .extract(read("{\"components\":[" + algorithm("AES-256") + "]}"))
                .assets()
                .get(0);

        assertThat(asset.evidence()).isNull();
        assertThat(asset.reportedOccurrences()).isZero();
    }
}
