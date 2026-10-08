package com.otilm.core.serialization.golden;

import com.fasterxml.jackson.core.util.DefaultIndenter;
import com.fasterxml.jackson.core.util.DefaultPrettyPrinter;
import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.ObjectWriter;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.JsonNodeFactory;
import com.fasterxml.jackson.databind.node.ObjectNode;
import java.io.IOException;
import java.io.InputStream;
import java.io.UncheckedIOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.fail;

/**
 * Compares serialized JSON against a committed golden file. Regenerate deliberately with
 * {@code -Dgolden.regenerate=true} and review the diff — see the package javadoc.
 */
final class GoldenJson {

    private static final String REGENERATE_PROPERTY = "golden.regenerate";

    private static final String RESOURCE_DIR = "golden";

    private static final Path SOURCE_DIR = Path.of("src", "test", "resources");

    private GoldenJson() {
    }

    /** @param goldenName file name under {@code src/test/resources/golden}, without the {@code .json} suffix */
    static void assertMatchesGolden(String goldenName, ObjectMapper mapper, Object value) {
        String actual = serialize(mapper, value);

        if (regenerating()) {
            write(jsonGolden(goldenName), actual);
            return;
        }

        String expected = read(jsonGolden(goldenName));
        assertThat(actual).describedAs(driftMessage(jsonGolden(goldenName))).isEqualTo(expected);
    }

    /**
     * Also asserts the value survives a deserialize/re-serialize cycle unchanged, catching a type whose write and read
     * sides disagree.
     *
     * @param readAs the declared type production reads the payload back as, which decides how polymorphic type
     * information is resolved
     */
    static void assertMatchesGoldenAndRoundTrips(String goldenName, ObjectMapper mapper, Object value,
            Class<?> readAs) {
        assertMatchesGolden(goldenName, mapper, value);

        String serialized = serialize(mapper, value);
        Object reread;
        try {
            reread = mapper.readValue(serialized, readAs);
        } catch (IOException e) {
            throw new UncheckedIOException("Golden '" + goldenName + "' could not be read back as " + readAs.getName(),
                    e);
        }

        assertThat(serialize(mapper, reread))
                .describedAs("Round-tripping golden '%s.json' through %s changed its JSON shape: its write and read "
                        + "sides disagree.", goldenName, readAs.getSimpleName())
                .isEqualTo(serialized);
    }

    /**
     * Compares JSON produced outside an {@link ObjectMapper} (Hibernate's {@code FormatMapper} returns a compact
     * string) after sorting object keys, so the key set and values are pinned but their order is not.
     * <p>
     * Order is unpinnable here: a {@code jsonb} column does not preserve it, and under a polymorphic declared type the
     * {@code @JsonTypeInfo} discriminator's position varies between JVM runs.
     */
    static void assertCanonicalizedJsonMatchesGolden(String goldenName, String rawJson) {
        String actual = canonicalize(rawJson);

        if (regenerating()) {
            write(jsonGolden(goldenName), actual);
            return;
        }

        assertThat(actual).describedAs(driftMessage(jsonGolden(goldenName))).isEqualTo(read(jsonGolden(goldenName)));
    }

    /**
     * Compares text no mapper here produced, such as a mapper fingerprint or a JMS message body.
     *
     * @param path golden path under {@code src/test/resources}, with its suffix
     */
    static void assertMatchesGoldenText(String path, String actual) {
        String normalized = normalize(actual);

        if (regenerating()) {
            write(path, normalized);
            return;
        }

        assertThat(normalized).describedAs(driftMessage(path)).isEqualTo(read(path));
    }

    private static String jsonGolden(String goldenName) {
        return RESOURCE_DIR + "/" + goldenName + ".json";
    }

    private static String driftMessage(String path) {
        return "Serialized output drifted from golden '" + path + "'. During the Jackson 3 migration this is a "
                + "finding to explain, not a test to update: trace the diff to a documented behaviour change before "
                + "regenerating with -D" + REGENERATE_PROPERTY + "=true.";
    }

    /**
     * Key-order-insensitive text for two payloads that must be equal. Floats become {@code BigDecimal} so {@code 1.5}
     * survives the rewrite.
     */
    static String canonicalize(String rawJson) {
        ObjectMapper reader = new ObjectMapper().enable(DeserializationFeature.USE_BIG_DECIMAL_FOR_FLOATS);
        try {
            return serialize(reader, sortKeys(reader.readTree(rawJson)));
        } catch (IOException e) {
            throw new UncheckedIOException("Could not canonicalize JSON for golden comparison", e);
        }
    }

    private static JsonNode sortKeys(JsonNode node) {
        if (node.isObject()) {
            ObjectNode sorted = JsonNodeFactory.instance.objectNode();
            node
                    .propertyStream()
                    .sorted(Map.Entry.comparingByKey())
                    .forEach(property -> sorted.set(property.getKey(), sortKeys(property.getValue())));
            return sorted;
        }
        if (node.isArray()) {
            ArrayNode mapped = JsonNodeFactory.instance.arrayNode();
            node.forEach(element -> mapped.add(sortKeys(element)));
            return mapped;
        }
        return node;
    }

    /** Pins {@code \n} and two-space indents; the platform default would fail goldens on another OS. */
    private static String serialize(ObjectMapper mapper, Object value) {
        DefaultIndenter indenter = new DefaultIndenter("  ", "\n");
        DefaultPrettyPrinter printer = new DefaultPrettyPrinter();
        printer.indentObjectsWith(indenter);
        printer.indentArraysWith(indenter);

        ObjectWriter writer = mapper.writer(printer);
        try {
            return writer.writeValueAsString(value);
        } catch (IOException e) {
            throw new UncheckedIOException("Could not serialize golden candidate", e);
        }
    }

    static boolean regenerating() {
        if (!Boolean.getBoolean(REGENERATE_PROPERTY)) {
            return false;
        }
        // Regeneration asserts nothing, so on CI the baseline would pass while verifying nothing.
        if (System.getenv("CI") != null) {
            throw new IllegalStateException("-D" + REGENERATE_PROPERTY + "=true must never be used on CI: it would "
                    + "rewrite the goldens instead of checking them, and the suite would pass while verifying nothing.");
        }
        return true;
    }

    static String read(String path) {
        Path onDisk = SOURCE_DIR.resolve(path);
        try {
            if (Files.exists(onDisk)) {
                return normalize(Files.readString(onDisk, StandardCharsets.UTF_8));
            }
            // Fall back to the classpath copy when the working directory is not the module root.
            try (InputStream stream = GoldenJson.class.getResourceAsStream("/" + path)) {
                if (stream == null) {
                    return fail("Golden '%s' does not exist. Create it by running with -D%s=true and reviewing "
                            + "the generated file before committing.", path, REGENERATE_PROPERTY);
                }
                return normalize(new String(stream.readAllBytes(), StandardCharsets.UTF_8));
            }
        } catch (IOException e) {
            throw new UncheckedIOException("Could not read golden '" + path + "'", e);
        }
    }

    private static void write(String path, String content) {
        Path target = SOURCE_DIR.resolve(path);
        try {
            Files.createDirectories(target.getParent());
            Files.writeString(target, content + "\n", StandardCharsets.UTF_8);
        } catch (IOException e) {
            throw new UncheckedIOException("Could not write golden '" + path + "'", e);
        }
    }

    /** Tolerate the trailing newline editors add and CRLF from a Windows checkout. */
    private static String normalize(String content) {
        return content.replace("\r\n", "\n").stripTrailing();
    }
}
