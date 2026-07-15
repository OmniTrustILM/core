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
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.stream.Stream;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Guards the four-way CI test split defined in pom.xml and used by the {@code .github/workflows/build_pr.yml} test matrix.
 * <p>
 * The core invariant: the four profiles must partition the runnable test classes — every class
 * surefire would run must be claimed by <em>exactly one</em> profile. A class claimed by none
 * silently never runs (coverage gap); a class claimed by two runs twice (double coverage, wasted
 * CI time). {@link #everyRunnableTestIsRunByExactlyOneCiProfile} proves the partition by replaying
 * surefire's include/exclude matching over the real test tree, so it catches drift in any pattern.
 * <p>
 * The heavy {@code integration.service} package is split by leading class letter (A-C vs D-Z) via a
 * shared {@code %regex} boundary — excluded from {@code test-integration-service-1}, included by
 * {@code test-integration-service-2}. {@link #flatServiceSplitBoundaryMustBeConsistent} keeps the two
 * sides identical so the flat classes cannot silently gap or double-run.
 * <p>
 * Additionally, every concrete test class in the service package must follow the naming convention
 * surefire matches (*Test, *Tests, *ITest); classes that don't are never picked up at all.
 */
class CiTestSplitTest {

    /** The profile ids the CI matrix runs, one per worker. Must partition the runnable test classes. */
    private static final List<String> CI_PROFILES = List.of(
            "test-non-integration",
            "test-integration-core",
            "test-integration-service-1",
            "test-integration-service-2");

    /**
     * Surefire's built-in default {@code <includes>}, applied to any profile that declares no
     * {@code <includes>} of its own (here: {@code test-non-integration}).
     */
    private static final List<String> SUREFIRE_DEFAULT_INCLUDES = List.of(
            "**/Test*.java", "**/*Test.java", "**/*Tests.java", "**/*TestCase.java");

    @Test
    void everyRunnableTestIsRunByExactlyOneCiProfile() throws Exception {
        Map<String, List<String>> includes = new HashMap<>();
        Map<String, List<String>> excludes = new HashMap<>();
        for (String profile : CI_PROFILES) {
            List<String> declared = profilePatterns(profile, "include");
            includes.put(profile, declared.isEmpty() ? SUREFIRE_DEFAULT_INCLUDES : declared);
            excludes.put(profile, profilePatterns(profile, "exclude"));
        }

        List<String> neverRun = new ArrayList<>();
        List<String> multiRun = new ArrayList<>();
        try (Stream<Path> stream = Files.walk(TEST_ROOT)) {
            List<Path> runnable = stream
                    .filter(p -> p.toString().endsWith(".java"))
                    .filter(TestClassTaxonomy::isRunnableTest)
                    .toList();
            for (Path p : runnable) {
                String rel = TEST_ROOT.relativize(p).toString().replace('\\', '/');
                List<String> claimedBy = CI_PROFILES.stream()
                        .filter(profile -> matchesAny(includes.get(profile), rel)
                                && !matchesAny(excludes.get(profile), rel))
                        .toList();
                if (claimedBy.isEmpty()) {
                    neverRun.add(rel);
                } else if (claimedBy.size() > 1) {
                    multiRun.add(rel + " -> " + claimedBy);
                }
            }
        }

        assertThat(neverRun)
                .describedAs("""
                        Runnable test classes claimed by no CI profile in pom.xml — surefire never runs them,
                        so their code is silently uncovered. Either the class name matches no profile <include>
                        (rename it to *Test/*Tests/*ITest, or under integration to *ITest), or the split patterns
                        have a gap. Fix the profiles in pom.xml so every runnable test is claimed exactly once.""")
                .isEmpty();
        assertThat(multiRun)
                .describedAs("""
                        Runnable test classes claimed by more than one CI profile in pom.xml — they run twice,
                        wasting CI time and double-counting coverage. The profile <includes>/<excludes> overlap.
                        Fix the profiles in pom.xml so every runnable test is claimed exactly once.""")
                .isEmpty();
    }

    @Test
    void flatServiceSplitBoundaryMustBeConsistent() throws Exception {
        List<String> shard1Excludes = profilePatterns("test-integration-service-1", "exclude");
        List<String> shard2Includes = profilePatterns("test-integration-service-2", "include");

        assertThat(shard2Includes)
                .describedAs("test-integration-service-2 must include exactly the flat-class %regex boundary")
                .hasSize(1);
        assertThat(shard1Excludes)
                .describedAs("""
                        test-integration-service-1 must exclude exactly the same flat-class boundary that
                        test-integration-service-2 includes. If the two drift apart, the integration.service
                        flat classes on the boundary either run twice or run in neither shard.""")
                .containsExactlyElementsOf(shard2Includes);
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
                        Surefire's include patterns key on those suffixes, so a differently-named class is never
                        run by any CI profile. Rename it to match the convention.""")
                .isEmpty();
    }

    /**
     * The {@code <include>}/{@code <exclude>} pattern texts declared under the given Maven profile's
     * surefire plugin in pom.xml. Parses pom.xml fresh on each call — these guards are not perf-sensitive.
     *
     * @param profileId the {@code <profile>} id, e.g. {@code test-integration-core}
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

    /** Whether a test class path (relative to {@link #TEST_ROOT}, {@code /}-separated) matches any pattern. */
    private static boolean matchesAny(List<String> patterns, String relPath) {
        return patterns.stream().anyMatch(pattern -> matches(pattern, relPath));
    }

    /**
     * Replays surefire's include/exclude matching for a single pattern against a test class path.
     * Supports both surefire pattern forms: {@code %regex[...]} (a Java regex over the path) and Ant
     * globs ({@code **}, {@code *}, {@code ?}). Anchored: the pattern must match the whole path.
     */
    private static boolean matches(String pattern, String relPath) {
        if (pattern.startsWith("%regex[") && pattern.endsWith("]")) {
            return relPath.matches(pattern.substring("%regex[".length(), pattern.length() - 1));
        }
        return relPath.matches(antGlobToRegex(pattern));
    }

    private static String antGlobToRegex(String glob) {
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < glob.length(); ) {
            if (glob.startsWith("**/", i)) {
                sb.append("(?:.*/)?");   // any number of directories, including none
                i += 3;
            } else if (glob.startsWith("**", i)) {
                sb.append(".*");
                i += 2;
            } else {
                char c = glob.charAt(i++);
                if (c == '*') {
                    sb.append("[^/]*");  // within a single path segment
                } else if (c == '?') {
                    sb.append("[^/]");  // a single character within a segment, never the separator
                } else if ("\\.[]{}()+-^$|".indexOf(c) >= 0) {
                    sb.append('\\').append(c);
                } else {
                    sb.append(c);
                }
            }
        }
        return sb.toString();
    }

    /**
     * Top-level sub-packages under com.otilm.core not yet migrated to the integration taxonomy.
     * Guard (3) is suppressed for these; the set shrinks to empty across per-package PRs.
     * Bare segment names (matched against the package segment after com/otilm/core), NOT path
     * fragments — a substring match would wrongly exempt e.g. any path merely containing "api".
     * <p>
     * This set is empty, so guard (3) is strict for all sub-packages.
     * {@link #ROOT_LEVEL_PENDING_MIGRATION} is {@code false} as well, so no exemption remains.
     */
    private static final Set<String> MIGRATION_ALLOWLIST = Set.of();

    /**
     * Whether root-level test files (directly under com/otilm/core, no sub-package) are exempt from
     * guard (3). The root sweep relocated the last such tests into the integration taxonomy, so this
     * is {@code false}: guard (3) is strict for root-level files too, and no exemption remains.
     */
    private static final boolean ROOT_LEVEL_PENDING_MIGRATION = false;

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
     * The integration CI profiles key their includes on the {@code *ITest.java} suffix, but
     * {@link #integrationRootContainsOnlyContextTests} only enforces context-loading. A runnable test
     * in the integration root not named {@code *ITest} would pass that guard yet be picked up by the {@code test-non-integration}.
     * This guard keeps the integration profile includes and the taxonomy guard aligned.
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
                        + "The integration CI profiles include only com/otilm/core/integration/**/*ITest.java, "
                        + "so these run in the test-non-integration leg and their coverage lands in the wrong artifact. "
                        + "Rename them to *ITest.")
                .isEmpty();
    }
}
