package com.otilm.core.cbom.asset.identity;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Stream;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.EnabledIfSystemProperty;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Extracts every document of a corpus exactly as ingest would and writes the result, so two revisions can be diffed row
 * by row -- and pins that result for the one corpus that lives in this repository.
 *
 * <p>
 * An instrument rather than a pin, on an external corpus: it ratifies no key, and a moved row is a result to read
 * rather than a failure. What it answers is the question the vector suite structurally cannot -- whether a rule change
 * moves a key on real producer output, and whether the partition merges or splits -- because every one of the ratified
 * vectors wraps a single component in a document of its own, and so sees neither cross-component reference resolution
 * nor document-scoped refutation. Two certificate-key collisions reached this branch green for exactly that reason: the
 * vectors carry no shape that could see them, and the external run is gated on a system property no CI job sets.
 *
 * <p>
 * <b>The miniature corpus closes that gap.</b> {@code src/test/resources/cbom/corpus} holds five authored documents --
 * no third-party content -- that reach every document-scoped rule: a suite code refuted by two names and one that an
 * alias must not refute, a stale suite block on an {@code algorithm} component that must be barred and one on an
 * untyped component that must contribute, a duplicated {@code bom-ref} and two public-key entries that must resolve to
 * nothing, a reference into a nested library, a content digest two certificates contradict, and a run of
 * distinguished-name spellings that must fold together or stay apart. {@link #theMiniatureCorpusKeysAsPinned} compares
 * the snapshot of that corpus with {@code src/test/resources/cbom/corpus-keys.tsv} on every build, so a key that moves
 * on a document-scoped shape fails CI and has to be re-pinned deliberately. Re-pinning is the external run pointed at
 * the miniature corpus:
 *
 * <pre>
 * mvn4 -o -B -Dtest=CorpusKeySnapshotTest -Dsurefire.failIfNoSpecifiedTests=false \
 *      -Dcorpus.dir=src/test/resources/cbom/corpus -Dcorpus.out=src/test/resources/cbom/corpus-keys.tsv test
 * </pre>
 *
 * <p>
 * <b>The population is ingest's, not the walk's.</b> An earlier revision keyed every component
 * {@link DocumentScope#walk} returned, so ordinary libraries, files and frameworks landed on
 * {@code backstop:unknown-type} and were counted as inventory: of the 8 048 components in the 2026-08-18 corpus, 3 054
 * are not cryptographic assets at all, and two {@code library} components sharing a name in different documents form a
 * size-2 key group that ingest cannot produce. Driving the snapshot through {@link CbomAssetExtractor#extract} keys the
 * components {@code isCryptographicAsset} admits, runs occurrence sanitisation, and reports a component that could not
 * be keyed as the skip ingest would record -- so the partition figures describe the inventory, and a regression in the
 * routing itself is visible as a change in the row count.
 *
 * <p>
 * It asserts on the run, not on any key: a corpus that yielded no rows, or a {@code .json} file that did not parse, is
 * a misconfigured run and not a corpus with nothing in it. Without that, pointing {@code corpus.dir} at the wrong
 * directory wrote an empty file and passed, and the empty diff that followed read as "no keys moved"; and a directory
 * of 196 files of which 150 failed to parse produced a plausible snapshot with no sign that most of it was missing.
 *
 * <p>
 * It is committed because the alternative is a number nobody can reproduce. core#2165's costing rests on runs of this
 * over the 2026-08-18 corpus, and the figures quoted there are this instrument's: a reviewer who wants to check them
 * has to be able to re-run it. Name the copy when quoting a figure -- the packaged tarball and the working directory it
 * was packaged from differ by seventeen duplicated files, and a count over the latter double-counts those documents.
 *
 * <p>
 * The external corpus is not in this repository -- it carries real third-party documents, some with secret-scanner
 * findings in them -- so that run is skipped unless it is told where one is:
 *
 * <pre>
 * mvn4 -o -B -Dtest=CorpusKeySnapshotTest -Dsurefire.failIfNoSpecifiedTests=false \
 *      -Dcorpus.dir=/path/to/corpora -Dcorpus.out=$PWD/keys.tsv test
 * </pre>
 *
 * <p>
 * The first line is a header counting documents, parse failures, walked components, keyed assets and skips. Each row
 * after it is {@code document<TAB>asset index<TAB>chain step<TAB>identity key}, or
 * {@code document<TAB>skip:index<TAB>THROWN<TAB>failure class} for a component ingest would skip, sorted, so two runs
 * diff with {@code diff} and a moved row names itself. A skip is a row rather than a failure because a crash is exactly
 * the kind of movement worth diffing -- that is how the surrogate defect in this branch was first priced.
 */
class CorpusKeySnapshotTest {

    private static final ObjectMapper MAPPER = new ObjectMapper();

    /** Resolved against the working directory, which Maven sets to the module root, as the fence's source root is. */
    static final Path MINIATURE_CORPUS = Path.of("src/test/resources/cbom/corpus");

    static final Path MINIATURE_PIN = Path.of("src/test/resources/cbom/corpus-keys.tsv");

    @Test
    @EnabledIfSystemProperty(named = "corpus.dir", matches = ".+")
    void snapshot() throws IOException {
        Path corpora = Path.of(System.getProperty("corpus.dir"));
        // Defaulted, because only corpus.dir gates the run: reading a second required property would meet anyone who
        // followed the skip condition alone with an NPE from Path.of(null) instead of a snapshot.
        Path out = Path.of(System.getProperty("corpus.out", "target/corpus-keys.tsv"));
        Files.createDirectories(out.toAbsolutePath().getParent());

        Snapshot snapshot = snapshot(corpora);
        Files.write(out, snapshot.lines(), StandardCharsets.UTF_8);

        assertThat(snapshot.rows()).describedAs("corpus at %s yielded no keyed components", corpora).isNotEmpty();
        assertThat(snapshot.unparseable())
                .describedAs(
                        "%d of %d .json files under %s did not parse; a corpus that does not parse is a wrong "
                                + "directory, not a corpus with nothing in it",
                        snapshot.unparseable(), snapshot.documents(), corpora)
                .isZero();
    }

    /**
     * The pin. Every row of the miniature corpus, header included, must be what the committed file says -- so a
     * document-scoped rule that moves a key fails here, in CI, and names the row that moved.
     */
    @Test
    void theMiniatureCorpusKeysAsPinned() throws IOException {
        Snapshot snapshot = snapshot(MINIATURE_CORPUS);

        assertThat(snapshot.unparseable()).describedAs("every authored document must parse").isZero();
        assertThat(snapshot.lines())
                .describedAs("the miniature corpus keys differently from %s. A moved row is a key move on a "
                        + "document-scoped shape the vectors cannot see; read it, and if it is intended re-pin with "
                        + "-Dcorpus.dir=%s -Dcorpus.out=%s", MINIATURE_PIN, MINIATURE_CORPUS, MINIATURE_PIN)
                .containsExactlyElementsOf(Files.readAllLines(MINIATURE_PIN, StandardCharsets.UTF_8));
    }

    /**
     * The pin above cannot tell a corpus that exercises the document-scoped rules from one that merely has many
     * components, so each rule is shown live here -- a shape that stopped reaching its rule would otherwise keep the
     * pin green while guarding nothing.
     */
    @Test
    void theMiniatureCorpusReachesEveryDocumentScopedRule() throws IOException {
        AssetNormalizer normalizer = new AssetNormalizer(IdentityTables.load());
        CbomAssetExtractor extractor = new CbomAssetExtractor(new CryptoAssetIdentity(normalizer));

        JsonNode references = MAPPER
                .readTree(MINIATURE_CORPUS.resolve("references-ambiguous-and-nested.cdx.json").toFile());
        Map<String, CbomAssetExtractor.ExtractedAsset> byName = byName(extractor.extract(references));
        assertThat(DocumentScope.of(references, normalizer).ambiguousRefs()).containsExactly("key-dup");
        assertThat(byName.get("cert-ambiguous").identityKey())
                .describedAs("a duplicated ref, a dangling ref and two public-key entries all resolve to nothing")
                .isEqualTo(byName.get("cert-dangling").identityKey())
                .isEqualTo(byName.get("cert-two-keys").identityKey());
        assertThat(byName.get("cert-related-asset-17").identityKey())
                .describedAs("the 1.7 related-asset entry, type spelled PublicKey, resolves like the 1.6 field")
                .isEqualTo(byName.get("cert-resolving").identityKey());
        assertThat(byName.get("cert-nested").identityKey())
                .describedAs("a reference into a nested library resolves, to a different key")
                .isNotEqualTo(byName.get("cert-resolving").identityKey())
                .isNotEqualTo(byName.get("cert-dangling").identityKey());

        JsonNode digests = MAPPER.readTree(MINIATURE_CORPUS.resolve("digests-refuted.cdx.json").toFile());
        byName = byName(extractor.extract(digests));
        assertThat(DocumentScope.of(digests, normalizer).refutedCertificateDigests()).hasSize(1);
        assertThat(byName.get("cert-shared-hash-alpha").chainStep())
                .describedAs("a digest two certificates contradict is unusable for both")
                .isEqualTo(byName.get("cert-shared-hash-beta").chainStep())
                .isEqualTo(ChainStep.CRT_DN_COMPOSITE.label());
        assertThat(byName.get("cert-unique-hash").chainStep()).isEqualTo(ChainStep.CRT_COMPONENT_HASH.label());
        assertThat(byName.get("cert-hash-agreeing-with-fingerprint").identityKey())
                .describedAs("a richer record agreeing with a sparser one on every field both state is not a "
                        + "contradiction, and the 1.7 fingerprint and hashes[] collapse onto one digest tier")
                .isEqualTo(byName.get("cert-fingerprint-17").identityKey());

        JsonNode suites = MAPPER.readTree(MINIATURE_CORPUS.resolve("suites-refuted-and-barred.cdx.json").toFile());
        assertThat(DocumentScope.of(suites, normalizer).refutedSuiteCodes())
                .describedAs("0x1301 is refuted by two names and 0x1304 by an untyped component; 0x1302 is stated only "
                        + "by a barred algorithm component and 0x1303 under an alias, so neither is refuted")
                .containsExactlyInAnyOrder(CipherSuites.code(MAPPER.readTree("[\"0x13\",\"0x01\"]")),
                        CipherSuites.code(MAPPER.readTree("[\"0x13\",\"0x04\"]")));
    }

    private static Map<String, CbomAssetExtractor.ExtractedAsset> byName(CbomAssetExtractor.Extraction extraction) {
        assertThat(extraction.skips()).isEmpty();
        Map<String, CbomAssetExtractor.ExtractedAsset> byName = new HashMap<>();
        for (CbomAssetExtractor.ExtractedAsset asset : extraction.assets()) {
            assertThat(byName.put(asset.componentName(), asset))
                    .describedAs("component names in the miniature corpus are unique within a document")
                    .isNull();
        }
        return byName;
    }

    private static CbomAssetExtractor extractor() {
        return new CbomAssetExtractor(new CryptoAssetIdentity(new AssetNormalizer(IdentityTables.load())));
    }

    /** One run over a corpus directory: the header counts and every row, sorted. */
    record Snapshot(int documents, int unparseable, int nonObject, int components, int skipped, List<String> rows) {

        String header() {
            return "# documents=" + documents + " parsed=" + (documents - unparseable - nonObject) + " unparseable="
                    + unparseable + " non-object=" + nonObject + " components=" + components + " keyed="
                    + (rows.size() - skipped) + " skipped=" + skipped;
        }

        List<String> lines() {
            List<String> lines = new ArrayList<>(rows.size() + 1);
            lines.add(header());
            lines.addAll(rows);
            return lines;
        }
    }

    static Snapshot snapshot(Path corpora) throws IOException {
        CbomAssetExtractor extractor = extractor();
        List<String> rows = new ArrayList<>();
        List<Path> documents;
        try (Stream<Path> walk = Files.walk(corpora)) {
            documents = walk.filter(p -> p.toString().endsWith(".json")).sorted().toList();
        }
        int unparseable = 0;
        int nonObject = 0;
        int components = 0;
        int skipped = 0;
        for (Path document : documents) {
            JsonNode root;
            try {
                root = MAPPER.readTree(document.toFile());
            } catch (IOException e) {
                unparseable++;
                continue;
            }
            if (!root.isObject()) {
                nonObject++;
                continue;
            }
            components += DocumentScope.walk(root).size();
            // Forward slashes whatever the platform, so the pinned file is the same on every checkout.
            String name = corpora.relativize(document).toString().replace('\\', '/');
            CbomAssetExtractor.Extraction extraction = extractor.extract(root);
            List<CbomAssetExtractor.ExtractedAsset> assets = extraction.assets();
            for (int i = 0; i < assets.size(); i++) {
                rows.add(name + "\t" + i + "\t" + assets.get(i).chainStep() + "\t" + assets.get(i).identityKey());
            }
            List<CbomAssetExtractor.Skip> skips = extraction.skips();
            for (int i = 0; i < skips.size(); i++) {
                rows.add(name + "\tskip:" + i + "\tTHROWN\t" + skips.get(i).reason());
            }
            skipped += skips.size();
        }
        rows.sort(Comparator.naturalOrder());
        return new Snapshot(documents.size(), unparseable, nonObject, components, skipped, rows);
    }
}
