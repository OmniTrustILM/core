package com.otilm.core.integration.service;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.otilm.api.exception.NotFoundException;
import com.otilm.api.model.client.certificate.SearchRequestDto;
import com.otilm.api.model.core.cryptoasset.CryptographicAssetDetailDto;
import com.otilm.api.model.core.cryptoasset.CryptographicAssetDto;
import com.otilm.api.model.core.cryptoasset.CryptographicAssetSourceDto;
import com.otilm.core.cbom.ingest.CbomAssetIngestService;
import com.otilm.core.cbom.sync.CbomSyncPolicy;
import com.otilm.core.dao.entity.Cbom;
import com.otilm.core.dao.repository.CbomRepository;
import com.otilm.core.security.authz.SecuredUUID;
import com.otilm.core.security.authz.SecurityFilter;
import com.otilm.core.service.CryptographicAssetExternalService;
import com.otilm.core.util.BaseSpringBootTest;
import java.io.IOException;
import java.nio.file.Path;
import java.time.OffsetDateTime;
import java.util.List;
import java.util.UUID;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.jdbc.core.JdbcTemplate;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * The source count and the sighting count an asset serves must never contradict each other, on the list or on the
 * detail. Real corpus documents go through the real extractor and writers: most of their components record no location,
 * which is exactly the shape that used to serve "2 source CBOMs, 0 occurrences".
 */
class CryptographicAssetSightingsITest extends BaseSpringBootTest {

    private static final Path CORPUS = Path.of("src/test/resources/cbom/corpus");

    private static final OffsetDateTime NOW = OffsetDateTime.parse("2026-09-25T10:00:00Z");

    private static final String UNLOCATED_ALGORITHM = "aes-256-gcm";

    private static final String LOCATED_MATERIAL = "seed-at-location";

    private final ObjectMapper mapper = new ObjectMapper();

    @Autowired
    private CbomAssetIngestService ingestService;

    @Autowired
    private CryptographicAssetExternalService cryptographicAssetService;

    @Autowired
    private CbomRepository cbomRepository;

    @Autowired
    private JdbcTemplate jdbcTemplate;

    @BeforeEach
    void ingestThreeDocuments() throws IOException {
        JsonNode materials = corpusDocument("materials-and-occurrences.cdx.json");
        JsonNode suites = corpusDocument("suites-refuted-and-barred.cdx.json");
        ingest("urn:uuid:5b1c2d3e-0000-4000-8000-000000000005", materials, NOW);
        ingest("urn:uuid:5b1c2d3e-0000-4000-8000-000000000001", suites, NOW.plusSeconds(1));
        ingest("urn:uuid:5b1c2d3e-0000-4000-8000-000000002299", algorithmWithTwoLocations(materials),
                NOW.plusSeconds(2));
    }

    @Test
    void sourcesWithoutLocationsStillServeOneSightingEach() throws NotFoundException {
        CryptographicAssetDto row = listedRow(UNLOCATED_ALGORITHM);
        CryptographicAssetDetailDto detail = detail(row);

        assertThat(row.getSourceCbomCount()).isEqualTo(3);
        assertThat(row.getSightingCount())
                .describedAs("1 + 1 for the unlocated reports, 2 for the located one")
                .isEqualTo(4);
        assertThat(detail.getSources())
                .extracting(CryptographicAssetSourceDto::getLocationCount)
                .containsExactly(0L, 0L, 2L);
    }

    @Test
    void aLocationKeyedMaterialRowCountsItsLocations() throws NotFoundException {
        CryptographicAssetDto row = listedRow(LOCATED_MATERIAL);

        assertThat(row.getSourceCbomCount()).isEqualTo(1);
        assertThat(row.getSightingCount()).isEqualTo(2);
        assertThat(detail(row).getSources())
                .extracting(CryptographicAssetSourceDto::getLocationCount)
                .containsExactly(2L);
    }

    @Test
    void everyServedRowCarriesAConsistentPairOnTheListAndTheDetail() throws NotFoundException {
        List<CryptographicAssetDto> rows = listAll();
        assertThat(rows).isNotEmpty();

        for (CryptographicAssetDto row : rows) {
            assertConsistent(row.getName(), row.getSourceCbomCount(), row.getSightingCount());
            CryptographicAssetDetailDto detail = detail(row);
            assertConsistent(row.getName(), detail.getSourceCbomCount(), detail.getSightingCount());
            assertThat(detail.getSourceCbomCount())
                    .describedAs("list and detail agree on %s", row.getName())
                    .isEqualTo(row.getSourceCbomCount());
            assertThat(detail.getSightingCount())
                    .describedAs("list and detail agree on %s", row.getName())
                    .isEqualTo(row.getSightingCount());
            long sightingsPerSource = detail
                    .getSources()
                    .stream()
                    .mapToLong(source -> Math.max(1, source.getLocationCount()))
                    .sum();
            assertThat(detail.getSightingCount())
                    .describedAs("the served sources add up for %s while every CBOM is visible and uncapped",
                            row.getName())
                    .isEqualTo(sightingsPerSource);
        }
    }

    /**
     * The stored {@code source_count} is maintained by the writers, but the served pair must not depend on it: even a
     * stale column cannot put sightings beside zero sources.
     */
    @Test
    void aStaleStoredSourceCountCannotServeSightingsWithoutSources() throws NotFoundException {
        CryptographicAssetDto before = listedRow(UNLOCATED_ALGORITHM);
        jdbcTemplate.update("UPDATE crypto_asset SET source_count = 0 WHERE uuid = ?", before.getUuid());

        CryptographicAssetDto row = listedRow(UNLOCATED_ALGORITHM);
        CryptographicAssetDetailDto detail = detail(row);

        assertThat(row.getSourceCbomCount()).isEqualTo(3);
        assertThat(row.getSightingCount()).isEqualTo(4);
        assertThat(detail.getSourceCbomCount()).isEqualTo(3);
        assertThat(detail.getSightingCount()).isEqualTo(4);
    }

    private static void assertConsistent(String name, int sourceCount, long sightingCount) {
        assertThat(sightingCount)
                .describedAs("sightings never below sources for %s", name)
                .isGreaterThanOrEqualTo(sourceCount);
        assertThat(sightingCount == 0)
                .describedAs("sightings are zero exactly when sources are zero for %s", name)
                .isEqualTo(sourceCount == 0);
    }

    private JsonNode corpusDocument(String fileName) throws IOException {
        return mapper.readTree(CORPUS.resolve(fileName).toFile());
    }

    /** A third document carrying the corpus's unlocated AES-256-GCM component, this time with two locations. */
    private JsonNode algorithmWithTwoLocations(JsonNode materials) {
        JsonNode algorithm = null;
        for (JsonNode component : materials.get("components")) {
            if ("alg-aes-256-gcm".equals(component.path("bom-ref").asText())) {
                algorithm = component;
            }
        }
        assertThat(algorithm).describedAs("the corpus still carries alg-aes-256-gcm").isNotNull();
        ObjectNode located = algorithm.deepCopy();
        ArrayNode occurrences = located.putObject("evidence").putArray("occurrences");
        occurrences.addObject().put("location", "src/tls.c").put("line", 10);
        occurrences.addObject().put("location", "src/kex.c").put("line", 20);
        ObjectNode document = mapper.createObjectNode();
        document.putArray("components").add(located);
        return document;
    }

    private void ingest(String serialNumber, JsonNode document, OffsetDateTime seenAt) {
        Cbom cbom = new Cbom();
        cbom.setSerialNumber(serialNumber);
        cbom.setVersion(1);
        cbom.setSpecVersion("1.6");
        UUID cbomUuid = cbomRepository.save(cbom).getUuid();
        ingestService.ingest(cbomUuid, document, seenAt, CbomSyncPolicy.DEFAULTS);
    }

    private List<CryptographicAssetDto> listAll() {
        return cryptographicAssetService
                .listCryptographicAssets(SecurityFilter.create(), new SearchRequestDto())
                .getItems();
    }

    private CryptographicAssetDto listedRow(String name) {
        List<CryptographicAssetDto> matches = listAll().stream().filter(row -> name.equals(row.getName())).toList();
        assertThat(matches).describedAs("exactly one row named %s", name).hasSize(1);
        return matches.get(0);
    }

    private CryptographicAssetDetailDto detail(CryptographicAssetDto row) throws NotFoundException {
        return cryptographicAssetService.getCryptographicAsset(SecuredUUID.fromUUID(row.getUuid()));
    }
}
