package com.otilm.core.architecture;

import java.io.IOException;
import java.io.InputStream;
import java.lang.reflect.Modifier;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeMap;
import java.util.TreeSet;
import java.util.regex.Pattern;
import java.util.stream.Stream;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathFactory;
import org.junit.jupiter.api.Test;
import org.w3c.dom.Document;
import org.w3c.dom.NodeList;
import org.yaml.snakeyaml.Yaml;

import static org.assertj.core.api.Assertions.assertThat;

/** Verifies that Build PR shards cover the test sources without overlap. */
class CiTestSplitTest {

    private static final Path TEST_ROOT = Path.of("src/test/java");
    private static final Path INTEGRATION_ROOT = TEST_ROOT.resolve("com/otilm/core/integration");
    private static final Path SHARD_ROOT = Path.of(".github/test-shards");
    private static final Path WORKFLOW = Path.of(".github/workflows/build_pr.yml");
    private static final String NON_INTEGRATION = "non-integration";
    private static final List<String> INTEGRATION_SHARDS = List
            .of("integration-1", "integration-2", "integration-3", "integration-4");

    private static final Pattern SUREFIRE_DEFAULT_INCLUDE_PATTERN = Pattern
            .compile("(?:Test.*|.*Test|.*Tests|.*TestCase)\\.java");
    private static final String INTEGRATION_EXCLUSION = "com/otilm/core/integration/.*ITest.*";

    @Test
    @SuppressWarnings("unchecked")
    void listsEachConfiguredShardExactlyOnce_whenReadingTheBuildPrTestMatrix() throws Exception {
        // given
        List<String> expected = Stream.concat(Stream.of(NON_INTEGRATION), INTEGRATION_SHARDS.stream()).toList();

        // when
        List<String> actual;
        try (InputStream input = Files.newInputStream(WORKFLOW)) {
            Map<?, ?> workflow = new Yaml().load(input);
            Map<?, ?> jobs = (Map<?, ?>) workflow.get("jobs");
            Map<?, ?> test = (Map<?, ?>) jobs.get("test");
            Map<?, ?> strategy = (Map<?, ?>) test.get("strategy");
            Map<?, ?> matrix = (Map<?, ?>) strategy.get("matrix");
            actual = (List<String>) matrix.get("group");
        }

        // then
        assertThat(actual)
                .describedAs("The Build PR matrix must run the non-integration shard and each integration manifest")
                .containsExactlyInAnyOrderElementsOf(expected);
    }

    @Test
    void assignsEachConcreteIntegrationTestExactlyOnce_whenUsingShardManifests() throws Exception {
        // given
        Set<String> integrationTests = concreteIntegrationTests();

        // when
        Map<Path, List<String>> assignmentsByManifest = new TreeMap<>();
        Map<String, List<String>> owners = new TreeMap<>();
        for (String shard : INTEGRATION_SHARDS) {
            Path manifest = SHARD_ROOT.resolve(shard + ".txt");
            List<String> assignments = Files
                    .readAllLines(manifest)
                    .stream()
                    .map(String::trim)
                    .filter(line -> !line.isEmpty() && !line.startsWith("#"))
                    .toList();
            assignmentsByManifest.put(manifest, assignments);
            assignments.forEach(path -> owners.computeIfAbsent(path, ignored -> new ArrayList<>()).add(shard));
        }

        List<String> unassigned = integrationTests.stream().filter(path -> !owners.containsKey(path)).toList();
        List<String> unexpected = owners.keySet().stream().filter(path -> !integrationTests.contains(path)).toList();
        List<String> duplicates = owners
                .entrySet()
                .stream()
                .filter(entry -> entry.getValue().size() > 1)
                .map(entry -> entry.getKey() + " -> " + entry.getValue())
                .toList();

        // then
        assignmentsByManifest
                .forEach((manifest, assignments) -> assertThat(assignments)
                        .describedAs("Integration test assignments in %s", manifest)
                        .isNotEmpty());
        assertThat(unassigned)
                .describedAs("Add each new or renamed integration test to one manifest under %s", SHARD_ROOT)
                .isEmpty();
        assertThat(unexpected)
                .describedAs("Integration manifests must list exact paths to concrete top-level *ITest.java classes")
                .isEmpty();
        assertThat(duplicates).describedAs("Integration tests must have exactly one manifest entry").isEmpty();
    }

    @Test
    void usesSurefireDefaultsOutsideIntegrationRoot_whenNonIntegrationProfileIsConfigured() throws Exception {
        // given — the checked-in POM and test sources

        // when
        List<String> includes = nonIntegrationProfilePatterns("include");
        List<String> excludes = nonIntegrationProfilePatterns("exclude");
        List<String> omitted;
        try (Stream<Path> stream = Files.walk(TEST_ROOT)) {
            omitted = stream
                    .filter(path -> !path.startsWith(INTEGRATION_ROOT))
                    .filter(path -> path.toString().endsWith(".java"))
                    .filter(TestClassTaxonomy::isRunnableTest)
                    .filter(path -> !SUREFIRE_DEFAULT_INCLUDE_PATTERN.matcher(path.getFileName().toString()).matches())
                    .map(CiTestSplitTest::relative)
                    .sorted()
                    .toList();
        }

        // then
        assertThat(includes).describedAs("The non-integration shard relies on Surefire's default includes").isEmpty();
        assertThat(excludes)
                .describedAs("The non-integration shard excludes integration tests and their nested classes")
                .containsExactly("%regex[" + INTEGRATION_EXCLUSION + "]");
        assertThat(omitted)
                .describedAs("Runnable non-integration tests must match Surefire's default includes")
                .isEmpty();
    }

    @Test
    void requiresJUnitNested_whenIntegrationInnerClassesMatchSurefireDefaults() throws Exception {
        // given — the checked-in integration test sources

        // when
        List<String> surefireNamed = new ArrayList<>();
        List<String> violations = new ArrayList<>();
        try (Stream<Path> stream = Files.walk(INTEGRATION_ROOT)) {
            List<Path> outers = stream
                    .filter(path -> path.toString().endsWith("ITest.java"))
                    .filter(TestClassTaxonomy::isRunnableTest)
                    .sorted()
                    .toList();
            for (Path outer : outers) {
                String path = relative(outer);
                for (TestClassTaxonomy.NestedClass nested : TestClassTaxonomy.nestedClasses(outer)) {
                    String nestedPath = path.substring(0, path.length() - ".java".length()) + "$" + nested.name()
                            + ".java";
                    if (!SUREFIRE_DEFAULT_INCLUDE_PATTERN
                            .matcher(Path.of(nestedPath).getFileName().toString())
                            .matches()) {
                        continue;
                    }
                    surefireNamed.add(nestedPath);
                    if (!nested.junitNested()) {
                        violations.add(nestedPath);
                    }
                }
            }
        }

        // then
        assertThat(surefireNamed)
                .describedAs("The integration tree must contain a nested class that matches Surefire's default naming")
                .isNotEmpty();
        assertThat(violations)
                .describedAs("Use @Nested or move the tests to a top-level *ITest listed in a manifest")
                .isEmpty();
    }

    @Test
    void everyRunnableTestInServicePackageMustMatchSplitPattern() throws IOException {
        List<String> splitSuffixes = List.of("Test.java", "Tests.java", "ITest.java");
        Path serviceDir = Path.of("src/test/java/com/otilm/core/service");

        List<String> violations;
        try (Stream<Path> stream = Files.walk(serviceDir)) {
            violations = stream
                    .filter(p -> p.toString().endsWith(".java"))
                    .filter(p -> splitSuffixes
                            .stream()
                            .noneMatch(suffix -> p.getFileName().toString().endsWith(suffix)))
                    .filter(TestClassTaxonomy::isRunnableTest)
                    .map(p -> serviceDir.relativize(p).toString())
                    .sorted()
                    .toList();
        }

        assertThat(violations).describedAs("""
                Test classes in service/ whose names don't end with Test, Tests, or ITest.
                Surefire's include patterns key on those suffixes, so a differently-named class is never
                run by any CI profile. Rename it to match the convention.""").isEmpty();
    }

    @Test
    void noContextTestOutsideIntegrationRoot() throws IOException {
        Map<String, String> graph = TestClassTaxonomy.parseExtends(TEST_ROOT);
        List<String> violations;
        try (Stream<Path> stream = Files.walk(TEST_ROOT)) {
            violations = stream
                    .filter(p -> p.toString().endsWith(".java"))
                    .filter(p -> !p.startsWith(INTEGRATION_ROOT))
                    .filter(TestClassTaxonomy::isRunnableTest)
                    .filter(p -> TestClassTaxonomy.loadsContext(p, graph))
                    .map(p -> TEST_ROOT.relativize(p).toString())
                    .sorted()
                    .toList();
        }
        assertThat(violations)
                .describedAs("Context-loading test classes found outside com.otilm.core.integration. "
                        + "Move them into the integration root, rename *ITest.")
                .isEmpty();
    }

    @Test
    void integrationRootContainsOnlyContextTests() throws IOException {
        assertThat(Files.exists(INTEGRATION_ROOT))
                .describedAs(
                        "Integration root %s must exist. A missing root means the guard would "
                                + "otherwise pass vacuously — the very mis-organisation it exists to catch.",
                        INTEGRATION_ROOT)
                .isTrue();
        Map<String, String> graph = TestClassTaxonomy.parseExtends(TEST_ROOT);
        List<String> violations;
        try (Stream<Path> stream = Files.walk(INTEGRATION_ROOT)) {
            violations = stream
                    .filter(p -> p.toString().endsWith(".java"))
                    .filter(TestClassTaxonomy::isRunnableTest)
                    .filter(p -> !TestClassTaxonomy.loadsContext(p, graph))
                    .map(p -> INTEGRATION_ROOT.relativize(p).toString())
                    .sorted()
                    .toList();
        }
        assertThat(violations)
                .describedAs("Non-context (pure unit) test classes found in the integration root. "
                        + "Move them out to a unit location and rename *Test.")
                .isEmpty();
    }

    @Test
    void requiresITestSuffix_whenIntegrationSourcesContainRunnableTests() throws Exception {
        // given
        boolean integrationRootExists = Files.exists(INTEGRATION_ROOT);

        // when
        List<String> violations = List.of();
        if (integrationRootExists) {
            try (Stream<Path> stream = Files.walk(INTEGRATION_ROOT)) {
                violations = stream
                        .filter(p -> p.toString().endsWith(".java"))
                        .filter(TestClassTaxonomy::isRunnableTest)
                        .filter(p -> !p.getFileName().toString().endsWith("ITest.java"))
                        .map(p -> INTEGRATION_ROOT.relativize(p).toString())
                        .sorted()
                        .toList();
            }
        }

        // then
        assertThat(integrationRootExists).describedAs("Integration root %s must exist.", INTEGRATION_ROOT).isTrue();
        assertThat(violations)
                .describedAs("Rename these integration tests to *ITest and list them in a manifest")
                .isEmpty();
    }

    // ── Helpers ───────────────────────────────────────────────────────────────

    /** Includes concrete classes whose tests are all inherited. */
    private static Set<String> concreteIntegrationTests() throws IOException, ClassNotFoundException {
        Set<String> tests = new TreeSet<>();
        List<Path> sources;
        try (Stream<Path> stream = Files.walk(INTEGRATION_ROOT)) {
            sources = stream.filter(path -> path.getFileName().toString().endsWith("ITest.java")).toList();
        }
        for (Path source : sources) {
            String path = relative(source);
            String binaryName = path.substring(0, path.length() - ".java".length()).replace('/', '.');
            Class<?> type = Class.forName(binaryName, false, CiTestSplitTest.class.getClassLoader());
            if (!Modifier.isAbstract(type.getModifiers())) {
                tests.add(path);
            }
        }
        return tests;
    }

    private static List<String> nonIntegrationProfilePatterns(String tag) throws Exception {
        DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
        factory.setNamespaceAware(false);
        Document pom = factory.newDocumentBuilder().parse(Path.of("pom.xml").toFile());
        XPath xpath = XPathFactory.newDefaultInstance().newXPath();
        String expression = "//profile[id='test-non-integration']//plugin[artifactId='maven-surefire-plugin']//" + tag;
        NodeList nodes = (NodeList) xpath.evaluate(expression, pom, XPathConstants.NODESET);
        List<String> patterns = new ArrayList<>(nodes.getLength());
        for (int index = 0; index < nodes.getLength(); index++) {
            patterns.add(nodes.item(index).getTextContent().trim());
        }
        return patterns;
    }

    private static String relative(Path path) {
        return TEST_ROOT.relativize(path).toString().replace('\\', '/');
    }
}
