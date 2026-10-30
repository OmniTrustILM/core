package com.otilm.core.architecture;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Stream;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathFactory;
import org.junit.jupiter.api.Test;
import org.w3c.dom.Document;
import org.w3c.dom.NodeList;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Guards the four-way CI test split defined in pom.xml and used by the {@code .github/workflows/build_pr.yml} test
 * matrix.
 * <p>
 * The core invariant: the four profiles must partition the runnable test classes — every class surefire would run must
 * be claimed by <em>exactly one</em> profile. A class claimed by none silently never runs (coverage gap); a class
 * claimed by two runs twice (double coverage, wasted CI time). {@link #everyRunnableTestIsRunByExactlyOneCiProfile}
 * proves the partition by replaying surefire's include/exclude matching over the real test tree, so it catches drift in
 * any pattern.
 * <p>
 * The heavy {@code integration.service} package is split by leading class letter (A-C vs D-Z) via a shared
 * {@code %regex} boundary, with heavy classes transferred from the first shard to the second.
 * <p>
 * Additionally, every concrete test class in the service package must follow the naming convention surefire matches
 * (*Test, *Tests, *ITest); classes that don't are never picked up at all.
 */
class CiTestSplitTest {

    private static final String NON_INTEGRATION_PROFILE = "test-non-integration";

    /** The profile ids the CI matrix runs, one per worker. Must partition the runnable test classes. */
    private static final List<String> CI_PROFILES = List
            .of(NON_INTEGRATION_PROFILE, "test-integration-core", "test-integration-service-1",
                    "test-integration-service-2");

    private static final String SERVICE_SPLIT_BOUNDARY = "%regex[com/otilm/core/integration/service/[D-Z][^/]*ITest.*]";

    /** {@code test-integration-core}'s exclude for the whole service package, which workers 3 and 4 own instead. */
    private static final String CORE_SERVICE_EXCLUDE = "com/otilm/core/integration/service/**/*ITest.java";

    private static final List<String> SERVICE_SHARD_TRANSFERS = List
            .of("com/otilm/core/integration/service/AcmeProfileServiceITest.java",
                    "com/otilm/core/integration/service/AcmeServiceITest.java",
                    "com/otilm/core/integration/service/CertificateServiceITest.java",
                    "com/otilm/core/integration/service/CryptographicKeyServiceITest.java");

    private static final List<String> CORE_SHARD_TRANSFERS = List
            .of("com/otilm/core/integration/cryptography/PQCITest.java",
                    "com/otilm/core/integration/search/TimeQualityConfigurationSearchITest.java");

    /**
     * Surefire's built-in default {@code <includes>}, applied to any profile that declares no {@code <includes>} of its
     * own (here: {@code test-non-integration}).
     */
    private static final List<String> SUREFIRE_DEFAULT_INCLUDES = List
            .of("**/Test*.java", "**/*Test.java", "**/*Tests.java", "**/*TestCase.java");

    @Test
    void everyRunnableTestIsRunByExactlyOneCiProfile() throws Exception {
        Map<String, List<String>> includes = profileIncludes();
        Map<String, List<String>> excludes = profileExcludes();

        List<String> neverRun = new ArrayList<>();
        List<String> multiRun = new ArrayList<>();
        try (Stream<Path> stream = Files.walk(TEST_ROOT)) {
            List<Path> runnable = stream
                    .filter(p -> p.toString().endsWith(".java"))
                    .filter(TestClassTaxonomy::isRunnableTest)
                    .toList();
            for (Path p : runnable) {
                String rel = relative(p);
                List<String> claimedBy = claimingProfiles(rel, includes, excludes);
                if (claimedBy.isEmpty()) {
                    neverRun.add(rel);
                } else if (claimedBy.size() > 1) {
                    multiRun.add(rel + " -> " + claimedBy);
                }
            }
        }

        assertThat(neverRun).describedAs("""
                Runnable test classes claimed by no CI profile in pom.xml — surefire never runs them,
                so their code is silently uncovered. Either the class name matches no profile <include>
                (rename it to *Test/*Tests/*ITest, or under integration to *ITest), or the split patterns
                have a gap. Fix the profiles in pom.xml so every runnable test is claimed exactly once.""").isEmpty();
        assertThat(multiRun).describedAs("""
                Runnable test classes claimed by more than one CI profile in pom.xml — they run twice,
                wasting CI time and double-counting coverage. The profile <includes>/<excludes> overlap.
                Fix the profiles in pom.xml so every runnable test is claimed exactly once.""").isEmpty();
    }

    @Test
    void serviceSplitPatternsMustBeConsistent() throws Exception {
        List<String> shard1Excludes = profilePatterns("test-integration-service-1", "exclude");
        List<String> shard2Includes = profilePatterns("test-integration-service-2", "include");
        List<String> expectedServicePatterns = new ArrayList<>();
        expectedServicePatterns.add(SERVICE_SPLIT_BOUNDARY);
        expectedServicePatterns.addAll(SERVICE_SHARD_TRANSFERS);

        List<String> expectedShard2Includes = new ArrayList<>(expectedServicePatterns);
        expectedShard2Includes.addAll(CORE_SHARD_TRANSFERS);

        assertThat(shard2Includes)
                .describedAs("test-integration-service-2 must include the boundary and all transfers")
                .containsExactlyInAnyOrderElementsOf(expectedShard2Includes);
        assertThat(shard1Excludes)
                .describedAs("""
                        test-integration-service-1 must exclude the service boundary and service transfers.
                        If these patterns drift, affected integration.service classes run twice or in neither shard.""")
                .containsExactlyInAnyOrderElementsOf(expectedServicePatterns);
    }

    @Test
    void coreTransfersMustBeExcludedFromCoreAndIncludedByServiceShard2() throws Exception {
        List<String> coreExcludes = profilePatterns("test-integration-core", "exclude");
        List<String> shard2Includes = profilePatterns("test-integration-service-2", "include");
        List<String> expectedCoreExcludes = new ArrayList<>();
        expectedCoreExcludes.add(CORE_SERVICE_EXCLUDE);
        expectedCoreExcludes.addAll(CORE_SHARD_TRANSFERS);

        assertThat(coreExcludes).containsExactlyInAnyOrderElementsOf(expectedCoreExcludes);
        assertThat(shard2Includes).containsAll(CORE_SHARD_TRANSFERS);
    }

    @Test
    void transferredClassesMustExist() {
        List<String> transfers = new ArrayList<>(SERVICE_SHARD_TRANSFERS);
        transfers.addAll(CORE_SHARD_TRANSFERS);

        List<String> missing = transfers
                .stream()
                .filter(path -> !Files.isRegularFile(TEST_ROOT.resolve(path)))
                .toList();

        assertThat(missing).describedAs("""
                Transferred test classes named in pom.xml that no longer exist under %s. Surefire ignores a
                pattern that matches nothing, so the class silently reverts to the shard its name implies and
                the worker balance these transfers bought degrades with no failing test. Update the pom
                patterns and the transfer constants here to the class's new path.""", TEST_ROOT).isEmpty();
    }

    @Test
    void nestedTestClassesInsideIntegrationTestsRunOnExactlyOneWorker() throws Exception {
        Map<String, List<String>> includes = profileIncludes();
        Map<String, List<String>> excludes = profileExcludes();

        List<String> surefireNamed = new ArrayList<>();
        List<String> violations = new ArrayList<>();
        try (Stream<Path> stream = Files.walk(INTEGRATION_ROOT)) {
            List<Path> outers = stream
                    .filter(p -> p.toString().endsWith(".java"))
                    .filter(TestClassTaxonomy::isRunnableTest)
                    .sorted()
                    .toList();
            for (Path outer : outers) {
                String outerRel = relative(outer);
                List<String> outerClaims = claimingProfiles(outerRel, includes, excludes);
                for (TestClassTaxonomy.NestedClass nested : TestClassTaxonomy.nestedClasses(outer)) {
                    String nestedRel = nestedClassPath(outerRel, nested.name());
                    boolean matchesSurefireDefaults = matchesAny(SUREFIRE_DEFAULT_INCLUDES, nestedRel);
                    if (!matchesSurefireDefaults && !nested.junitNested()) {
                        continue; // an ordinary helper class no profile could ever claim as a test
                    }
                    if (matchesSurefireDefaults) {
                        surefireNamed.add(nestedRel);
                    }
                    List<String> claims = claimingProfiles(nestedRel, includes, excludes);
                    if (claims.contains(NON_INTEGRATION_PROFILE)) {
                        violations
                                .add(nestedRel + " claimed by " + NON_INTEGRATION_PROFILE
                                        + " while its enclosing class runs on " + outerClaims);
                    } else if (nested.junitNested()) {
                        if (!outerClaims.containsAll(claims)) {
                            violations
                                    .add(nestedRel + " claimed by " + claims + " but its enclosing class runs on "
                                            + outerClaims);
                        }
                    } else if (claims.size() != 1) {
                        violations
                                .add(nestedRel + " is not a @Nested class, so it only runs if a profile claims it "
                                        + "directly, but it is claimed by " + claims);
                    }
                }
            }
        }

        assertThat(surefireNamed)
                .describedAs(
                        """
                                No nested class under %s carries a name surefire's default <includes> would claim, so this guard
                                proves nothing about the duplicate-execution regression it exists to catch. Either the nested-class
                                parsing broke, or the tree changed shape — re-derive the guard against what it now contains.""",
                        INTEGRATION_ROOT)
                .isNotEmpty();
        assertThat(violations).describedAs("""
                Nested classes inside integration tests that do not run on exactly one CI worker. Surefire scans
                Outer$Nested.class as its own entry, so a nested class claimed by a worker that does not run its
                enclosing class runs twice across the matrix, and a non-@Nested one claimed by nobody never runs.
                Fix the profile patterns in pom.xml — the integration excludes must keep their trailing .* so they
                cover the $-suffixed entries.""").isEmpty();
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

    /**
     * The {@code <include>}/{@code <exclude>} pattern texts declared under the given Maven profile's surefire plugin in
     * pom.xml. Parses pom.xml fresh on each call — these guards are not perf-sensitive.
     *
     * @param profileId the {@code <profile>} id, e.g. {@code test-integration-core}
     * @param tag {@code include} or {@code exclude}
     */
    private static List<String> profilePatterns(String profileId, String tag) throws Exception {
        DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
        dbf.setNamespaceAware(false);
        Document pom = dbf.newDocumentBuilder().parse(Path.of("pom.xml").toFile());
        XPath xpath = XPathFactory.newDefaultInstance().newXPath();

        String expression = "//profile[id='" + profileId + "']//plugin[artifactId='maven-surefire-plugin']//" + tag;
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
     * The declared {@code <includes>} per profile, falling back to surefire's defaults where a profile declares none.
     */
    private static Map<String, List<String>> profileIncludes() throws Exception {
        Map<String, List<String>> includes = new HashMap<>();
        for (String profile : CI_PROFILES) {
            List<String> declared = profilePatterns(profile, "include");
            includes.put(profile, declared.isEmpty() ? SUREFIRE_DEFAULT_INCLUDES : declared);
        }
        return includes;
    }

    private static Map<String, List<String>> profileExcludes() throws Exception {
        Map<String, List<String>> excludes = new HashMap<>();
        for (String profile : CI_PROFILES) {
            excludes.put(profile, profilePatterns(profile, "exclude"));
        }
        return excludes;
    }

    /** The profiles whose surefire patterns claim the given class path — an include matches and no exclude does. */
    private static List<String> claimingProfiles(String relPath, Map<String, List<String>> includes,
            Map<String, List<String>> excludes) {
        return CI_PROFILES
                .stream()
                .filter(profile -> matchesAny(includes.get(profile), relPath)
                        && !matchesAny(excludes.get(profile), relPath))
                .toList();
    }

    /** A test class path relative to {@link #TEST_ROOT}, {@code /}-separated on every platform. */
    private static String relative(Path javaFile) {
        return TEST_ROOT.relativize(javaFile).toString().replace('\\', '/');
    }

    /**
     * The path surefire matches a nested class by: the enclosing class file with {@code $Nested} appended to its name.
     */
    private static String nestedClassPath(String outerRelPath, String nestedName) {
        return outerRelPath.substring(0, outerRelPath.length() - ".java".length()) + "$" + nestedName + ".java";
    }

    /**
     * Replays surefire's include/exclude matching for a single pattern against a test class path. Supports both
     * surefire pattern forms: {@code %regex[...]} (a Java regex over the path) and Ant globs ({@code **}, {@code *},
     * {@code ?}). Anchored: the pattern must match the whole path.
     */
    private static boolean matches(String pattern, String relPath) {
        if (pattern.startsWith("%regex[") && pattern.endsWith("]")) {
            return relPath.matches(pattern.substring("%regex[".length(), pattern.length() - 1));
        }
        return relPath.matches(antGlobToRegex(pattern));
    }

    private static String antGlobToRegex(String glob) {
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < glob.length();) {
            if (glob.startsWith("**/", i)) {
                sb.append("(?:.*/)?"); // any number of directories, including none
                i += 3;
            } else if (glob.startsWith("**", i)) {
                sb.append(".*");
                i += 2;
            } else {
                char c = glob.charAt(i++);
                if (c == '*') {
                    sb.append("[^/]*"); // within a single path segment
                } else if (c == '?') {
                    sb.append("[^/]"); // a single character within a segment, never the separator
                } else if ("\\.[]{}()+-^$|".indexOf(c) >= 0) {
                    sb.append('\\').append(c);
                } else {
                    sb.append(c);
                }
            }
        }
        return sb.toString();
    }

    private static final Path TEST_ROOT = Path.of("src/test/java");
    private static final Path INTEGRATION_ROOT = TEST_ROOT.resolve("com/otilm/core/integration");

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

    /**
     * The integration CI profiles key their includes on the {@code *ITest.java} suffix, but
     * {@link #integrationRootContainsOnlyContextTests} only enforces context-loading. A runnable test in the
     * integration root not named {@code *ITest} would pass that guard yet be picked up by the
     * {@code test-non-integration}. This guard keeps the integration profile includes and the taxonomy guard aligned.
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
                    .sorted()
                    .toList();
        }
        assertThat(violations)
                .describedAs("Runnable test classes in the integration root whose names don't end with ITest. "
                        + "The integration CI profiles include only com/otilm/core/integration/**/*ITest.java, "
                        + "so these run in the test-non-integration leg and their coverage lands in the wrong artifact. "
                        + "Rename them to *ITest.")
                .isEmpty();
    }
}
