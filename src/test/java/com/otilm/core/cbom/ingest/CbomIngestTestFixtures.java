package com.otilm.core.cbom.ingest;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.otilm.core.cbom.sync.CbomSyncPolicy;
import java.util.Arrays;
import java.util.stream.Collectors;

/**
 * The CycloneDX stubs and the configuration fixture the ingest tests share.
 *
 * <p>
 * One copy, because three drifted independently: the same document shape was spelled out in the ingest unit test, in
 * the withdrawal unit test and in the inventory integration test, so a change to {@code CbomAssetExtractor}'s input
 * expectations had three places to be found. Everything here is a value -- no Spring, no context, nothing a test class
 * has to import a module for.
 */
public final class CbomIngestTestFixtures {

    /** Shared, not built per call: an ObjectMapper is expensive and these stubs are read thousands of times. */
    private static final ObjectMapper MAPPER = new ObjectMapper();

    private CbomIngestTestFixtures() {
    }

    /** A document of algorithm components, one per name given, each keying to a distinct asset. */
    public static JsonNode algorithmDocument(String... names) {
        return read(Arrays
                .stream(names)
                .map(CbomIngestTestFixtures::algorithm)
                .collect(Collectors.joining(",", "{\"components\":[", "]}")));
    }

    /** One algorithm component, reported at the given occurrence locations. */
    public static JsonNode algorithmSeenAt(String name, String... locations) {
        final String occurrences = Arrays
                .stream(locations)
                .map(location -> "{\"location\":\"" + location + "\"}")
                .collect(Collectors.joining(",", "[", "]"));
        return read("{\"components\":[{\"type\":\"cryptographic-asset\",\"name\":\"" + name + "\","
                + "\"cryptoProperties\":{\"assetType\":\"algorithm\",\"algorithmProperties\":{}},"
                + "\"evidence\":{\"occurrences\":" + occurrences + "}}]}");
    }

    public static String algorithm(String name) {
        return "{\"type\":\"cryptographic-asset\",\"name\":\"" + name + "\",\"cryptoProperties\":"
                + "{\"assetType\":\"algorithm\",\"algorithmProperties\":{}}}";
    }

    /** The production defaults with one batch size substituted; what a run hands the ingest and the withdrawal. */
    public static CbomSyncPolicy policy(int assetBatchSize) {
        return new CbomSyncPolicy(CbomSyncPolicy.DEFAULT_OVERLAP, CbomSyncPolicy.DEFAULT_SKIPPED_RETRY_RUNS,
                CbomSyncPolicy.DEFAULT_MAX_INGEST_DOCUMENTS, CbomSyncPolicy.DEFAULT_SKIP_RETENTION_DAYS,
                CbomSyncPolicy.DEFAULT_PAGE_SIZE, true, assetBatchSize, CbomSyncPolicy.DEFAULT_INGEST_RETRY_AFTER);
    }

    /** As {@link #policy(int)}, with the asset-ingest kill switch off. */
    public static CbomSyncPolicy policyWithIngestDisabled() {
        return new CbomSyncPolicy(CbomSyncPolicy.DEFAULT_OVERLAP, CbomSyncPolicy.DEFAULT_SKIPPED_RETRY_RUNS,
                CbomSyncPolicy.DEFAULT_MAX_INGEST_DOCUMENTS, CbomSyncPolicy.DEFAULT_SKIP_RETENTION_DAYS,
                CbomSyncPolicy.DEFAULT_PAGE_SIZE, false, CbomSyncPolicy.DEFAULT_ASSET_BATCH_SIZE,
                CbomSyncPolicy.DEFAULT_INGEST_RETRY_AFTER);
    }

    public static JsonNode read(String json) {
        try {
            return MAPPER.readTree(json);
        } catch (JsonProcessingException e) {
            throw new IllegalStateException(e);
        }
    }
}
