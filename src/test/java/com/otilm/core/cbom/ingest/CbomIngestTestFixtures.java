package com.otilm.core.cbom.ingest;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.otilm.core.config.CbomSyncProperties;
import java.time.Duration;
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

    /** The seven-arg record, with ingest enabled and everything but the batch size at its production default. */
    public static CbomSyncProperties properties(int assetBatchSize) {
        return new CbomSyncProperties(1000, Duration.ofSeconds(60), 3, true, assetBatchSize, 50,
                Duration.ofMinutes(30));
    }

    /** As {@link #properties(int)}, with {@code cbom.sync.asset-ingest-enabled} off. */
    public static CbomSyncProperties propertiesWithIngestDisabled() {
        return new CbomSyncProperties(1000, Duration.ofSeconds(60), 3, false, 100, 50, Duration.ofMinutes(30));
    }

    public static JsonNode read(String json) {
        try {
            return MAPPER.readTree(json);
        } catch (JsonProcessingException e) {
            throw new IllegalStateException(e);
        }
    }
}
