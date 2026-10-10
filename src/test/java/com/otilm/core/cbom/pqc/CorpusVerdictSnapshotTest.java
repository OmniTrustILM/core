package com.otilm.core.cbom.pqc;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.otilm.core.cbom.asset.CryptoAssetIdentityFields;
import com.otilm.core.cbom.asset.identity.AssetNormalizer;
import com.otilm.core.cbom.asset.identity.CbomAssetExtractor;
import com.otilm.core.cbom.asset.identity.CryptoAssetIdentity;
import com.otilm.core.cbom.asset.identity.IdentityTables;
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
 * Evaluates every asset of a corpus as the sweep would read its freshly ingested row and writes the verdicts, so two
 * revisions of the rule set can be diffed row by row: which rows move, and from which rule to which.
 *
 * <p>
 * An instrument, like {@code CorpusKeySnapshotTest}: it ratifies no verdict, asserts on the run and not on any answer,
 * and is skipped unless told where a corpus is. The identity key is not written -- the row is addressed by document and
 * extraction index, which is what a diff needs.
 *
 * <p>
 * References are not resolved, since there is no inventory to resolve them against, so every certificate and protocol
 * reads under its no-reference deferral; the instrument measures the algorithm and material rules.
 *
 * <pre>
 * mvn4 -o -B -Dtest=CorpusVerdictSnapshotTest -Dsurefire.failIfNoSpecifiedTests=false \
 *      -Dcorpus.dir=/path/to/corpora -Dcorpus.out=$PWD/verdicts.tsv test
 * </pre>
 */
class CorpusVerdictSnapshotTest {

    private static final ObjectMapper MAPPER = new ObjectMapper();

    @Test
    @EnabledIfSystemProperty(named = "corpus.dir", matches = ".+")
    void snapshot() throws IOException {
        Path corpora = Path.of(System.getProperty("corpus.dir"));
        Path out = Path.of(System.getProperty("corpus.out", "target/corpus-verdicts.tsv"));
        Files.createDirectories(out.toAbsolutePath().getParent());

        List<String> rows = snapshot(corpora);
        Files.write(out, rows, StandardCharsets.UTF_8);

        assertThat(rows).describedAs("corpus at %s yielded no evaluated assets", corpora).isNotEmpty();
    }

    /**
     * {@code document<TAB>index<TAB>type<TAB>name<TAB>verdict<TAB>ruleId}, sorted; a document that does not parse is
     * skipped.
     */
    static List<String> snapshot(Path corpora) throws IOException {
        AssetNormalizer normalizer = new AssetNormalizer(IdentityTables.load());
        CbomAssetExtractor extractor = new CbomAssetExtractor(new CryptoAssetIdentity(normalizer));
        PqcEvaluator evaluator = new PqcEvaluator(normalizer);
        List<Path> documents;
        try (Stream<Path> walk = Files.walk(corpora)) {
            documents = walk.filter(p -> p.toString().endsWith(".json")).sorted().toList();
        }
        List<String> rows = new ArrayList<>();
        for (Path document : documents) {
            JsonNode root;
            try {
                root = MAPPER.readTree(document.toFile());
            } catch (IOException e) {
                continue;
            }
            if (!root.isObject()) {
                continue;
            }
            String name = corpora.relativize(document).toString().replace('\\', '/');
            List<CbomAssetExtractor.ExtractedAsset> assets = extractor.extract(root).assets();
            for (int i = 0; i < assets.size(); i++) {
                CbomAssetExtractor.ExtractedAsset asset = assets.get(i);
                CryptoAssetIdentityFields row = CryptoAssetIdentityFields
                        .of(PqcEvaluator.assetTypeOf(asset.normalized().assetType()), asset.normalized())
                        .normalized();
                JsonNode properties = asset.retainedProperties();
                PqcDecision decision = evaluator
                        .evaluate(evaluator.fromStoredRow(row, properties),
                                PqcEvaluator.nistQuantumSecurityLevel(properties));
                rows
                        .add(name + "\t" + i + "\t" + row.assetType().getCode() + "\t" + row.name() + "\t"
                                + decision.verdict().getCode() + "\t" + decision.ruleId());
            }
        }
        rows.sort(Comparator.naturalOrder());
        return rows;
    }
}
