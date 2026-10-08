package com.otilm.core.serialization.golden;

import com.fasterxml.jackson.core.StreamReadFeature;
import com.fasterxml.jackson.core.StreamWriteFeature;
import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.MapperFeature;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationConfig;
import com.fasterxml.jackson.databind.SerializationFeature;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Collectors;
import org.springframework.http.ProblemDetail;

/** Wire output compared against goldens recorded on the Spring Boot 3.5 line, under {@code src/test/resources/wire}. */
public final class WireGolden {

    private static final String DIR = "wire/";

    /** A feature line of {@link #fingerprint}; group 1 is the feature's key, such as {@code ser INDENT_OUTPUT}. */
    private static final Pattern FEATURE = Pattern.compile("((?:mapper|ser|de|read|write) \\w+)=(?:true|false)");

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
        for (StreamReadFeature feature : StreamReadFeature.values()) {
            lines.add("read " + feature + "=" + mapper.getFactory().isEnabled(feature));
        }
        for (StreamWriteFeature feature : StreamWriteFeature.values()) {
            lines.add("write " + feature + "=" + mapper.getFactory().isEnabled(feature));
        }
        lines.add("inclusion " + config.getDefaultPropertyInclusion());
        lines.add("visibility " + config.getDefaultVisibilityChecker());
        Class<?> problemDetailMixIn = mapper.findMixInClassFor(ProblemDetail.class);
        lines.add("mixIns " + mapper.mixInCount());
        lines.add("mixIn ProblemDetail " + (problemDetailMixIn == null ? "none" : problemDetailMixIn.getName()));
        lines.add("dateFormat " + config.getDateFormat().getClass().getName());
        lines.add("epoch " + config.getDateFormat().format(new Date(0)));
        lines.add("timeZone " + config.getTimeZone().getID());
        lines.add("naming " + config.getPropertyNamingStrategy());
        return String.join("\n", lines) + "\n";
    }

    /** Boot 4 moved its Jackson 2 modules to another package, and a module's id is its class name. */
    private static String simpleName(Object moduleId) {
        String id = String.valueOf(moduleId);
        return id.substring(id.lastIndexOf('.') + 1);
    }

    /**
     * Jackson minors add feature constants, so a feature the golden has not recorded is left out and only a recorded
     * setting that changed fails. Regenerating records the new ones.
     */
    public static void assertFingerprintMatches(String name, ObjectMapper mapper) {
        String actual = fingerprint(mapper);
        if (!GoldenJson.regenerating()) {
            Set<String> recorded = GoldenJson
                    .read(DIR + name)
                    .lines()
                    .map(FEATURE::matcher)
                    .filter(Matcher::matches)
                    .map(feature -> feature.group(1))
                    .collect(Collectors.toSet());
            actual = actual.lines().filter(line -> isRecorded(line, recorded)).collect(Collectors.joining("\n"));
        }
        assertMatches(name, actual);
    }

    private static boolean isRecorded(String line, Set<String> recordedFeatures) {
        Matcher feature = FEATURE.matcher(line);
        return !feature.matches() || recordedFeatures.contains(feature.group(1));
    }

    /** Regenerating with -Dgolden.regenerate=true is for the 3.5 line only. */
    public static void assertMatches(String name, String actual) {
        GoldenJson.assertMatchesGoldenText(DIR + name, actual);
    }
}
