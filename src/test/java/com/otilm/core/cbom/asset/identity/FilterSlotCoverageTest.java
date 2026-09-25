package com.otilm.core.cbom.asset.identity;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Map;
import java.util.Set;
import java.util.TreeMap;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Pins, per asset type, how many assets reach the inventory with no filter slot beyond the OID. Such an asset is stored
 * but unreachable by the family, curve, primitive and size filters, so a rise here is a regression in what the
 * inventory can find, and a fall is an improvement to re-pin deliberately.
 *
 * <p>
 * Two populations, because the ratified vectors are single-component documents where a cross-component reference
 * resolves only through their {@code refTargets}, while the miniature corpus is whole documents.
 */
class FilterSlotCoverageTest {

    private static final String VECTORS = "cbom/identity-key-vectors.json";

    private static final String UNROUTABLE = "<unroutable>";

    private static final ObjectMapper MAPPER = new ObjectMapper();

    private final AssetNormalizer normalizer = new AssetNormalizer(IdentityTables.load());

    private final CryptoAssetIdentity identity = new CryptoAssetIdentity(normalizer);

    private static boolean anySlotBeyondOid(NormalizedAsset asset) {
        return asset.family() != null || asset.primitive() != null || asset.parameterSet() != null
                || asset.curve() != null || asset.mode() != null || asset.padding() != null || asset.variant() != null;
    }

    @Test
    void theRatifiedVectorsNormalizedAlone() throws IOException {
        Map<String, Integer> blind = new TreeMap<>();
        for (JsonNode vector : vectorFile().get("vectors")) {
            try {
                count(blind, normalizer.normalize(vector.get("component")).asset());
            } catch (IllegalArgumentException refused) {
                // A refused vector reaches no inventory row.
            }
        }

        assertThat(blind)
                .containsExactlyInAnyOrderEntriesOf(Map
                        .of(UNROUTABLE, 4, CbomNames.ASSET_TYPE_CERTIFICATE, 32, CbomNames.ASSET_TYPE_PROTOCOL, 30,
                                CbomNames.ASSET_TYPE_RELATED_CRYPTO_MATERIAL, 37));
    }

    @Test
    void theRatifiedVectorsWithReferencesResolved() throws IOException {
        Map<String, Integer> blind = new TreeMap<>();
        for (JsonNode vector : vectorFile().get("vectors")) {
            try {
                count(blind,
                        identity
                                .of(vector.get("component"), DocumentScope.of(documentAround(vector), normalizer),
                                        Set.of())
                                .asset());
            } catch (IllegalArgumentException refused) {
                // A refused vector reaches no inventory row.
            }
        }

        assertThat(blind)
                .containsExactlyInAnyOrderEntriesOf(Map
                        .of(UNROUTABLE, 4, CbomNames.ASSET_TYPE_CERTIFICATE, 24, CbomNames.ASSET_TYPE_PROTOCOL, 30,
                                CbomNames.ASSET_TYPE_RELATED_CRYPTO_MATERIAL, 37));
    }

    @Test
    void theMiniatureCorpus() throws IOException {
        CbomAssetExtractor extractor = new CbomAssetExtractor(identity);
        Map<String, Integer> blind = new TreeMap<>();
        int extracted = 0;
        try (var documents = Files.list(CorpusKeySnapshotTest.MINIATURE_CORPUS)) {
            for (Path document : documents.sorted().toList()) {
                if (!document.getFileName().toString().endsWith(".json")) {
                    continue;
                }
                for (CbomAssetExtractor.ExtractedAsset asset : extractor
                        .extract(MAPPER.readTree(document.toFile()))
                        .assets()) {
                    extracted++;
                    count(blind, asset.normalized());
                }
            }
        }

        assertThat(extracted).isEqualTo(53);
        assertThat(blind)
                .containsExactlyInAnyOrderEntriesOf(Map
                        .of(UNROUTABLE, 3, CbomNames.ASSET_TYPE_CERTIFICATE, 27, CbomNames.ASSET_TYPE_PROTOCOL, 6,
                                CbomNames.ASSET_TYPE_RELATED_CRYPTO_MATERIAL, 8));
    }

    private static void count(Map<String, Integer> blind, NormalizedAsset asset) {
        if (!anySlotBeyondOid(asset)) {
            blind.merge(asset.assetType() == null ? UNROUTABLE : asset.assetType(), 1, Integer::sum);
        }
    }

    private static JsonNode vectorFile() throws IOException {
        try (InputStream stream = FilterSlotCoverageTest.class.getClassLoader().getResourceAsStream(VECTORS)) {
            assertThat(stream).describedAs("the ratified vectors must be on the test classpath").isNotNull();
            return MAPPER.readTree(stream);
        }
    }

    private static JsonNode documentAround(JsonNode vector) {
        ArrayNode components = MAPPER.createArrayNode();
        components.add(vector.get("component"));
        JsonNode targets = vector.get("refTargets");
        if (targets != null && targets.isArray()) {
            targets.forEach(components::add);
        }
        ObjectNode document = MAPPER.createObjectNode();
        document.set("components", components);
        return document;
    }
}
