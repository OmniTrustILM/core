package com.otilm.core.serialization.golden;

import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.MapperFeature;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationConfig;
import com.fasterxml.jackson.databind.SerializationFeature;
import java.util.ArrayList;
import java.util.List;

/** Wire output compared against goldens recorded on the Spring Boot 3.5 line, under {@code src/test/resources/wire}. */
public final class WireGolden {

    private static final String DIR = "wire/";

    private WireGolden() {
    }

    /** The mapper configuration that decides the bytes it writes, one setting per line. */
    public static String fingerprint(ObjectMapper mapper) {
        SerializationConfig config = mapper.getSerializationConfig();
        List<String> lines = new ArrayList<>();
        mapper.getRegisteredModuleIds().stream().map(id -> "module " + simpleName(id)).sorted().forEach(lines::add);
        for (MapperFeature feature : MapperFeature.values()) {
            lines.add("mapper " + feature + "=" + config.isEnabled(feature));
        }
        for (SerializationFeature feature : SerializationFeature.values()) {
            lines.add("ser " + feature + "=" + config.isEnabled(feature));
        }
        for (DeserializationFeature feature : DeserializationFeature.values()) {
            lines.add("de " + feature + "=" + mapper.getDeserializationConfig().isEnabled(feature));
        }
        lines.add("inclusion " + config.getDefaultPropertyInclusion());
        lines.add("dateFormat " + config.getDateFormat().getClass().getName());
        lines.add("timeZone " + config.getTimeZone().getID());
        lines.add("naming " + config.getPropertyNamingStrategy());
        return String.join("\n", lines) + "\n";
    }

    /** Boot 4 moved its Jackson 2 modules to another package, and a module's id is its class name. */
    private static String simpleName(Object moduleId) {
        String id = String.valueOf(moduleId);
        return id.substring(id.lastIndexOf('.') + 1);
    }

    /** Regenerating with -Dgolden.regenerate=true is for the 3.5 line only. */
    public static void assertMatches(String name, String actual) {
        GoldenJson.assertMatchesGoldenText(DIR + name, actual);
    }
}
