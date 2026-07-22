package com.otilm.core.architecture;

import java.io.IOException;
import java.io.UncheckedIOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.HashMap;
import java.util.Map;
import java.util.TreeSet;
import java.util.stream.Stream;

/**
 * Canonical, order-insensitive signature for a test class's Spring context configuration: the union of
 * - imported module simple-names,
 * - local mock TYPE simple-names,
 * - active profiles,
 * - @TestPropertySource args,
 * - @DirtiesContext mode,
 * - nested @TestConfiguration class simple-names,
 * - verbatim @SpringBootTest arguments, and
 * - @AutoConfigure* annotation names.
 *
 * Two classes with equal signatures are expected to share one cached context. Import order is not a signature axis
 */
final class ContextSignature {

    private ContextSignature() {}

    /** Builds simple-class-name -> file for a whole tree, once. */
    static Map<String, Path> filesBySimpleName(Path testRoot) {
        try (Stream<Path> s = Files.walk(testRoot)) {
            Map<String, Path> map = new HashMap<>();
            s.filter(p -> p.toString().endsWith(".java"))
                    .forEach(p -> map.putIfAbsent(stripExtension(p.getFileName().toString()), p));
            return map;
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }

    static String of(String startSimpleName, Map<String, String> extendsGraph, Map<String, Path> filesByName) {
        TreeSet<String> imports = new TreeSet<>();
        TreeSet<String> mocks = new TreeSet<>();
        TreeSet<String> profiles = new TreeSet<>();
        TreeSet<String> props = new TreeSet<>();
        TreeSet<String> dirties = new TreeSet<>();
        TreeSet<String> configs = new TreeSet<>();
        TreeSet<String> springBootTest = new TreeSet<>();
        TreeSet<String> autoconfig = new TreeSet<>();

        String simple = startSimpleName;
        int hops = 0;
        while (simple != null && hops++ < 50) {
            Path file = filesByName.get(simple);
            if (file != null) {
                TestClassTaxonomy.ContextTokens t = TestClassTaxonomy.annotationTokens(file);
                imports.addAll(t.imports());
                mocks.addAll(t.mocks());
                profiles.addAll(t.profiles());
                props.addAll(t.props());
                dirties.addAll(t.dirties());
                configs.addAll(t.configs());
                springBootTest.addAll(t.springBootTest());
                autoconfig.addAll(t.autoconfig());
            }
            simple = extendsGraph.get(simple);
        }
        return "imports=" + imports + ";mocks=" + mocks + ";profiles=" + profiles
                + ";props=" + props + ";dirties=" + dirties
                + ";configs=" + configs + ";sbt=" + springBootTest
                + ";autoconfig=" + autoconfig;
    }

    static int distinctCount(Path testRoot) {
        Map<String, String> graph = TestClassTaxonomy.parseExtends(testRoot);
        Map<String, Path> byName = filesBySimpleName(testRoot);
        try (Stream<Path> s = Files.walk(testRoot)) {
            return (int) s.filter(p -> p.toString().endsWith(".java"))
                    .filter(TestClassTaxonomy::isRunnableTest)
                    .filter(p -> TestClassTaxonomy.loadsContext(p, graph))
                    .map(p -> of(stripExtension(p.getFileName().toString()), graph, byName))
                    .distinct()
                    .count();
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }

    private static String stripExtension(String n) {
        return n.endsWith(".java") ? n.substring(0, n.length() - 5) : n;
    }
}
