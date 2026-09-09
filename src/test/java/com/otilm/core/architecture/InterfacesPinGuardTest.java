package com.otilm.core.architecture;

import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeSet;
import org.junit.jupiter.api.Test;
import org.yaml.snakeyaml.Yaml;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Pins the two list memberships that stop an unmerged {@code interfaces} override reaching {@code main}.
 * <p>
 * A pull request may redirect its build at an unmerged {@code interfaces} pull request's snapshot by carrying a
 * {@code Depends-On:} or {@code Interfaces-Version:} marker in its body. Two lists in {@code build_pr.yml} keep that
 * safe, and both are silent when they drift.
 * <p>
 * Dropping {@code pin-gate} from the aggregate job's {@code needs} leaves every check green while an override is active
 * — "Interfaces pin" is not itself a required context, so that list is the whole enforcement. Adding a job that
 * compiles the tree without the resolved argument reddens a coupled pull request against the mainline snapshot instead,
 * with diagnostics pointing at the new job rather than at the missing override.
 * <p>
 * Neither surfaces anywhere near the edit that caused it; this test fails at the edit instead. It loads no Spring
 * context, so it does not affect {@link ContextSignatureGuardTest#BASELINE}.
 */
class InterfacesPinGuardTest {

    private static final Path WORKFLOW = Path.of(".github/workflows/build_pr.yml");

    private static final String GATE_JOB = "pin-gate";
    private static final String AGGREGATE_JOB = "build";
    private static final String OVERRIDE = "$MVNARG";

    /** Maven lifecycle phases that compile the tree, and so resolve {@code com.otilm:interfaces}. */
    private static final Set<String> BUILDING_PHASES = Set
            .of("compile", "test-compile", "test", "package", "verify", "install", "deploy");

    /**
     * The jobs that compile the tree today. Asserted explicitly so that a detection which silently stops matching
     * cannot make {@link #everyTreeBuildingJobPassesTheResolvedOverride()} pass over an empty set.
     */
    private static final Set<String> EXPECTED_BUILDING_JOBS = Set.of("compile", "test", "package", "generated");

    @Test
    void aggregateJobDependsOnThePinGate() throws IOException {
        assertThat(needsOf(AGGREGATE_JOB))
                .describedAs(
                        "'%s' is reached only through '%s' needs - \"Interfaces pin\" is not itself a required "
                                + "context, so removing it from that list lets an active override merge",
                        GATE_JOB, AGGREGATE_JOB)
                .contains(GATE_JOB);
    }

    @Test
    void everyTreeBuildingJobPassesTheResolvedOverride() throws IOException {
        Set<String> missing = new TreeSet<>();
        jobs()
                .forEach((name, job) -> mavenInvocations(job)
                        .stream()
                        .filter(InterfacesPinGuardTest::compilesTheTree)
                        .filter(command -> !command.contains(OVERRIDE))
                        .forEach(command -> missing.add(name)));

        assertThat(missing)
                .describedAs(
                        "every job running a Maven phase that compiles the tree must pass %s, or a pull request "
                                + "holding an override builds against the mainline interfaces snapshot instead",
                        OVERRIDE)
                .isEmpty();
    }

    @Test
    void theDetectionStillRecognisesTheBuildingJobs() throws IOException {
        Set<String> detected = new TreeSet<>();
        jobs()
                .forEach((name, job) -> mavenInvocations(job)
                        .stream()
                        .filter(InterfacesPinGuardTest::compilesTheTree)
                        .forEach(command -> detected.add(name)));

        assertThat(detected)
                .describedAs("the phase detection must keep matching the jobs that build the tree; a set that shrinks "
                        + "to nothing would make the override check above pass vacuously")
                .containsExactlyInAnyOrderElementsOf(EXPECTED_BUILDING_JOBS);
    }

    @SuppressWarnings("unchecked")
    private static Map<String, Object> jobs() throws IOException {
        try (InputStream in = Files.newInputStream(WORKFLOW)) {
            Map<String, Object> root = new Yaml().load(in);
            return new LinkedHashMap<>((Map<String, Object>) root.get("jobs"));
        }
    }

    @SuppressWarnings("unchecked")
    private static List<String> needsOf(String jobName) throws IOException {
        Object needs = ((Map<String, Object>) jobs().get(jobName)).get("needs");
        return needs instanceof String single ? List.of(single) : (List<String>) needs;
    }

    /**
     * The {@code mvn} command lines a job runs, with backslash continuations joined. Matching whole lines rather than
     * searching the script keeps prose that merely mentions a phase — comments, error messages — out of the result.
     */
    @SuppressWarnings("unchecked")
    private static List<String> mavenInvocations(Object job) {
        List<String> invocations = new ArrayList<>();
        Object steps = ((Map<String, Object>) job).get("steps");
        if (steps == null) {
            return invocations;
        }
        for (Object step : (List<Object>) steps) {
            Object run = ((Map<String, Object>) step).get("run");
            if (!(run instanceof String script)) {
                continue;
            }
            Arrays
                    .stream(script.replace("\\\n", " ").split("\n"))
                    .map(String::strip)
                    .filter(line -> line.startsWith("mvn "))
                    .forEach(invocations::add);
        }
        return invocations;
    }

    /**
     * True when the invocation names a lifecycle phase rather than only plugin goals such as {@code spotless:check}.
     */
    private static boolean compilesTheTree(String invocation) {
        return Arrays
                .stream(invocation.split("\\s+"))
                .filter(token -> !token.startsWith("-"))
                .anyMatch(BUILDING_PHASES::contains);
    }
}
