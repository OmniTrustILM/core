package com.otilm.core.architecture;

import org.junit.jupiter.api.Test;
import org.w3c.dom.Document;
import org.w3c.dom.NodeList;

import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathFactory;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.stream.Stream;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Guards the three-way CI test split defined in pom.xml.
 * <p>
 * The test-non-services Maven profile's <excludes> must equal the union of the test-services profile's <includes> and
 * the test-integration profile's <includes>. A pattern present on one side but absent from the union causes affected tests to
 * run twice (double coverage noise) or not at all (silent gap).
 * <p>
 * Additionally, every concrete test class in the service package must follow the naming
 * convention those patterns match (*Test, *Tests, *ITest). Classes that don't match are
 * not picked up by test-services and run in test-non-services instead, silently misclassifying
 * service tests as non-service tests.
 */
class CiTestSplitTest {

    @Test
    void restExcludesMustEqualUnionOfServiceAndIntegrationIncludes() throws Exception {
        List<String> serviceIncludes = profilePatterns("test-services", "include");
        List<String> integrationIncludes = profilePatterns("test-integration", "include");
        List<String> restExcludes = profilePatterns("test-non-services", "exclude");

        List<String> union = new ArrayList<>(serviceIncludes);
        union.addAll(integrationIncludes);

        assertThat(serviceIncludes)
                .describedAs("test-services profile must define at least one <include> pattern in pom.xml")
                .isNotEmpty();
        assertThat(restExcludes)
                .describedAs("""
                        test-non-services <excludes> must equal test-services <includes> UNION test-integration <includes>.
                        A pattern present in one side but not the other causes tests to run twice or not at all.
                        Update all three profiles together whenever the split patterns change.""")
                .containsExactlyInAnyOrderElementsOf(union);
    }

    @Test
    void integrationRootIsIncludedByIntegrationProfileAndExcludedByOthers() throws Exception {
        List<String> integrationIncludes = profilePatterns("test-integration", "include");
        List<String> serviceExcludes = profilePatterns("test-services", "exclude");
        List<String> restExcludes = profilePatterns("test-non-services", "exclude");

        assertThat(integrationIncludes)
                .describedAs("test-integration must include the single integration root pattern")
                .containsExactly("com/otilm/core/integration/**/*ITest.java");
        assertThat(serviceExcludes)
                .describedAs("test-services must exclude the integration root so integration tests don't double-run")
                .contains("com/otilm/core/integration/**/*ITest.java");
        assertThat(restExcludes)
                .describedAs("test-non-services must exclude the integration root")
                .contains("com/otilm/core/integration/**/*ITest.java");
    }

    @Test
    void everyRunnableTestInServicePackageMustMatchSplitPattern() throws IOException {
        List<String> splitSuffixes = List.of("Test.java", "Tests.java", "ITest.java");
        Path serviceDir = Path.of("src/test/java/com/otilm/core/service");

        List<String> violations;
        try (Stream<Path> stream = Files.walk(serviceDir)) {
            violations = stream
                    .filter(p -> p.toString().endsWith(".java"))
                    .filter(p -> splitSuffixes.stream().noneMatch(suffix -> p.getFileName().toString().endsWith(suffix)))
                    .filter(TestClassTaxonomy::isRunnableTest)
                    .map(p -> serviceDir.relativize(p).toString())
                    .sorted()
                    .toList();
        }

        assertThat(violations)
                .describedAs("""
                        Test classes in service/ whose names don't end with Test, Tests, or ITest.
                        They are not picked up by the test-services Maven profile and run in test-non-services instead.
                        Either rename them to match the pattern, or update both <includes> in test-services
                        and <excludes> in test-non-services in pom.xml to cover the new suffix.""")
                .isEmpty();
    }

    /**
     * The {@code <include>}/{@code <exclude>} pattern texts declared under the given Maven profile's
     * surefire plugin in pom.xml. Parses pom.xml fresh on each call — these guards are not perf-sensitive.
     *
     * @param profileId the {@code <profile>} id, e.g. {@code test-services}
     * @param tag       {@code include} or {@code exclude}
     */
    private static List<String> profilePatterns(String profileId, String tag) throws Exception {
        DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
        dbf.setNamespaceAware(false);
        Document pom = dbf.newDocumentBuilder().parse(Path.of("pom.xml").toFile());
        XPath xpath = XPathFactory.newDefaultInstance().newXPath();

        String expression = "//profile[id='" + profileId
                + "']//plugin[artifactId='maven-surefire-plugin']//" + tag;
        NodeList nodes = (NodeList) xpath.evaluate(expression, pom, XPathConstants.NODESET);
        List<String> result = new ArrayList<>(nodes.getLength());
        for (int i = 0; i < nodes.getLength(); i++) {
            result.add(nodes.item(i).getTextContent().trim());
        }
        return result;
    }

    /**
     * Top-level sub-packages under com.otilm.core not yet migrated to the integration taxonomy.
     * Guard (3) is suppressed for these; the set shrinks to empty across per-package PRs.
     * Bare segment names (matched against the package segment after com/otilm/core), NOT path
     * fragments — a substring match would wrongly exempt e.g. any path merely containing "api".
     */
    private static final Set<String> MIGRATION_ALLOWLIST = Set.of(
            "service", "util", "signing", "messaging", "security", "migration", "search",
            "dao", "api", "attribute", "config", "tasks", "events", "repository", "auth",
            "aop", "model", "provisioning", "evaluator", "cryptography", "cluster");

    /**
     * Root-level test files live directly in com/otilm/core (no sub-package) — e.g. ApplicationTests,
     * AcmeUtilTest, JmsNetworkChaosTest — and are migrated in the final root-sweep PR. Guard (3)
     * exempts them until then. Set to false in that final PR to make the guard strict.
     */
    private static final boolean ROOT_LEVEL_PENDING_MIGRATION = true;

    private static final Path TEST_ROOT = Path.of("src/test/java");
    private static final Path INTEGRATION_ROOT = TEST_ROOT.resolve("com/otilm/core/integration");

    /** The com.otilm.core sub-package a test file belongs to, or empty for a root-level file. */
    private static Optional<String> topLevelPackage(Path relToTestRoot) {
        String[] parts = relToTestRoot.toString().replace('\\', '/').split("/");
        // parts: com, otilm, core, <segment>, ..., File.java  (root-level file has length 4)
        return parts.length > 4 ? Optional.of(parts[3]) : Optional.empty();
    }

    private static boolean pendingMigration(Path relToTestRoot) {
        return topLevelPackage(relToTestRoot)
                .map(MIGRATION_ALLOWLIST::contains)
                .orElse(ROOT_LEVEL_PENDING_MIGRATION);
    }

    @Test
    void noContextTestOutsideIntegrationRoot() throws IOException {
        Map<String,String> graph = TestClassTaxonomy.parseExtends(TEST_ROOT);
        List<String> violations;
        try (Stream<Path> stream = Files.walk(TEST_ROOT)) {
            violations = stream
                    .filter(p -> p.toString().endsWith(".java"))
                    .filter(p -> !p.startsWith(INTEGRATION_ROOT))
                    .filter(p -> !pendingMigration(TEST_ROOT.relativize(p)))
                    .filter(TestClassTaxonomy::isRunnableTest)
                    .filter(p -> TestClassTaxonomy.loadsContext(p, graph))
                    .map(p -> TEST_ROOT.relativize(p).toString())
                    .sorted().toList();
        }
        assertThat(violations)
                .describedAs("Context-loading test classes found outside com.otilm.core.integration "
                        + "in an already-migrated package. Move them into the integration root, rename *ITest.")
                .isEmpty();
    }

    @Test
    void migrationAllowlistEntriesMustStillHavePendingMigration() throws IOException {
        Map<String, String> graph = TestClassTaxonomy.parseExtends(TEST_ROOT);
        Path corePackage = TEST_ROOT.resolve("com/otilm/core");
        List<String> staleEntries = new ArrayList<>();
        for (String segment : MIGRATION_ALLOWLIST) {
            Path pkgDir = corePackage.resolve(segment);
            if (!Files.exists(pkgDir)) {
                staleEntries.add(segment + " (no such package directory)");
                continue;
            }
            boolean hasPending;
            try (Stream<Path> stream = Files.walk(pkgDir)) {
                hasPending = stream
                        .filter(p -> p.toString().endsWith(".java"))
                        .filter(p -> !p.startsWith(INTEGRATION_ROOT))
                        .filter(TestClassTaxonomy::isRunnableTest)
                        .anyMatch(p -> TestClassTaxonomy.loadsContext(p, graph));
            }
            if (!hasPending) {
                staleEntries.add(segment);
            }
        }
        assertThat(staleEntries)
                .describedAs("""
                        MIGRATION_ALLOWLIST entries with no remaining pending (runnable, context-loading) test
                        outside the integration root. Guard (3) is silently suppressed for these packages, so a
                        context test added there later would go undetected. Remove each listed segment from
                        MIGRATION_ALLOWLIST — the set must self-prune to empty as packages are migrated.""")
                .isEmpty();
    }

    @Test
    void integrationRootContainsOnlyContextTests() throws IOException {
        assertThat(Files.exists(INTEGRATION_ROOT))
                .describedAs("Integration root %s must exist. A missing root means the guard would "
                        + "otherwise pass vacuously — the very mis-organisation it exists to catch.", INTEGRATION_ROOT)
                .isTrue();
        Map<String,String> graph = TestClassTaxonomy.parseExtends(TEST_ROOT);
        List<String> violations;
        try (Stream<Path> stream = Files.walk(INTEGRATION_ROOT)) {
            violations = stream
                    .filter(p -> p.toString().endsWith(".java"))
                    .filter(TestClassTaxonomy::isRunnableTest)
                    .filter(p -> !TestClassTaxonomy.loadsContext(p, graph))
                    .map(p -> INTEGRATION_ROOT.relativize(p).toString())
                    .sorted().toList();
        }
        assertThat(violations)
                .describedAs("Non-context (pure unit) test classes found in the integration root. "
                        + "Move them out to a unit location and rename *Test.")
                .isEmpty();
    }

    /**
     * The test-integration profile's <include> keys on the {@code *ITest.java} suffix, but
     * {@link #integrationRootContainsOnlyContextTests} only enforces context-loading. A runnable
     * test in the integration root not named {@code *ITest} would pass that guard yet be picked up
     * by the test-non-services leg (its coverage lands in the wrong artifact), because the
     * non-services exclude is {@code *ITest}-only. This guard keeps the profile include and the
     * taxonomy guard aligned.
     */
    @Test
    void integrationRootRunnableTestsMustBeNamedITest() throws IOException {
        assertThat(Files.exists(INTEGRATION_ROOT))
                .describedAs("Integration root %s must exist.", INTEGRATION_ROOT)
                .isTrue();
        List<String> violations;
        try (Stream<Path> stream = Files.walk(INTEGRATION_ROOT)) {
            violations = stream
                    .filter(p -> p.toString().endsWith(".java"))
                    .filter(TestClassTaxonomy::isRunnableTest)
                    .filter(p -> !p.getFileName().toString().endsWith("ITest.java"))
                    .map(p -> INTEGRATION_ROOT.relativize(p).toString())
                    .sorted().toList();
        }
        assertThat(violations)
                .describedAs("Runnable test classes in the integration root whose names don't end with ITest. "
                        + "The test-integration Maven profile includes only com/otilm/core/integration/**/*ITest.java, "
                        + "so these run in the test-non-services leg and their coverage lands in the wrong artifact. "
                        + "Rename them to *ITest.")
                .isEmpty();
    }
}
