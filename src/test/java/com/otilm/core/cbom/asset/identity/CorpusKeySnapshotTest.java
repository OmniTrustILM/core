package com.otilm.core.cbom.asset.identity;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import java.util.stream.Stream;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.EnabledIfSystemProperty;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Extracts every document of an external corpus exactly as ingest would and writes the result, so two revisions can be
 * diffed row by row.
 *
 * <p>
 * An instrument rather than a pin: it ratifies no key, and a moved row is a result to read rather than a failure. What
 * it answers is the question the vector suite structurally cannot -- whether a rule change moves a key on real producer
 * output, and whether the partition merges or splits -- because the vectors wrap each component in a document of its
 * own and so see neither cross-component reference resolution nor document-scoped refutation.
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
 * has to be able to re-run it.
 *
 * <p>
 * The corpus is not in this repository -- it carries real third-party documents, some with secret-scanner findings in
 * them -- so the test is skipped unless it is told where one is:
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
@EnabledIfSystemProperty(named = "corpus.dir", matches = ".+")
class CorpusKeySnapshotTest {

    private static final ObjectMapper MAPPER = new ObjectMapper();

    @Test
    void snapshot() throws IOException {
        Path corpora = Path.of(System.getProperty("corpus.dir"));
        // Defaulted, because only corpus.dir gates the run: reading a second required property would meet anyone who
        // followed the skip condition alone with an NPE from Path.of(null) instead of a snapshot.
        Path out = Path.of(System.getProperty("corpus.out", "target/corpus-keys.tsv"));
        Files.createDirectories(out.toAbsolutePath().getParent());
        CbomAssetExtractor extractor = new CbomAssetExtractor(
                new CryptoAssetIdentity(new AssetNormalizer(IdentityTables.load())));
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
            String name = corpora.relativize(document).toString();
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
        String header = "# documents=" + documents.size() + " parsed=" + (documents.size() - unparseable - nonObject)
                + " unparseable=" + unparseable + " non-object=" + nonObject + " components=" + components + " keyed="
                + (rows.size() - skipped) + " skipped=" + skipped;
        List<String> lines = new ArrayList<>(rows.size() + 1);
        lines.add(header);
        lines.addAll(rows);
        Files.write(out, lines, StandardCharsets.UTF_8);

        assertThat(rows).describedAs("corpus at %s yielded no keyed components", corpora).isNotEmpty();
        assertThat(unparseable)
                .describedAs("%d of %d .json files under %s did not parse; a corpus that does not parse is a wrong "
                        + "directory, not a corpus with nothing in it", unparseable, documents.size(), corpora)
                .isZero();
    }
}
