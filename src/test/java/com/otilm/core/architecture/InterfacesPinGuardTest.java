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
import java.util.regex.Pattern;
import org.junit.jupiter.api.Test;
import org.yaml.snakeyaml.Yaml;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Pins what stops an unmerged {@code interfaces} override from reaching {@code main}.
 * <p>
 * Three lines carry the merge block, each removable as a tidy-up: {@code pin-gate} in the aggregate job's
 * {@code needs}; the aggregate's {@code !cancelled()}, without which it is skipped when the gate fails and a skipped
 * required check counts as passing; and its scan failing on a non-successful upstream. A fourth, {@code $MVNARG} on
 * every job that compiles the tree, keeps a coupled pull request from reddening for the wrong reason.
 * <p>
 * All four are silent when they drift, and none surfaces near the edit that caused it. Loads no Spring context, so it
 * does not affect {@link ContextSignatureGuardTest#BASELINE}.
 */
class InterfacesPinGuardTest {

    private static final Path WORKFLOW = Path.of(".github/workflows/build_pr.yml");

    private static final String GATE_JOB = "pin-gate";
    private static final String AGGREGATE_JOB = "build";
    private static final String OVERRIDE = "$MVNARG";

    /** A Maven call anywhere in the line, so that {@code cd x && mvn ...} and the wrapper are seen too. */
    private static final Pattern MAVEN_INVOCATION = Pattern
            .compile("(^|&&\\s*|\\|\\|\\s*|;\\s*|\\|\\s*|\\(\\s*)\\.?/?mvnw?\\s");

    /** Maven lifecycle phases that compile the tree, and so resolve {@code com.otilm:interfaces}. */
    private static final Set<String> BUILDING_PHASES = Set
            .of("compile", "test-compile", "test", "package", "verify", "install", "deploy", "process-classes",
                    "process-test-classes", "integration-test", "prepare-package");

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
    void aggregateJobRunsEvenWhenAnUpstreamFails() throws IOException {
        assertThat(String.valueOf(job(AGGREGATE_JOB).get("if")))
                .describedAs("without !cancelled() the aggregate is skipped whenever '%s' fails, and GitHub counts a "
                        + "skipped required check as passing - which is the failure this gate exists to prevent",
                        GATE_JOB)
                .contains("!cancelled()");
    }

    @Test
    void aggregateFailsOnAnyUpstreamThatDidNotSucceed() throws IOException {
        assertThat(stepSource(job(AGGREGATE_JOB)))
                .describedAs("the scan over the needs context is what turns a failed '%s' into a red Build; running "
                        + "on !cancelled() without it would report success instead", GATE_JOB)
                .contains("toJSON(needs)")
                .contains("exit 1");
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
    private static Map<String, Object> job(String jobName) throws IOException {
        return (Map<String, Object>) jobs().get(jobName);
    }

    /** Every step's {@code run} and {@code env} together — an expression can reach a script through either. */
    @SuppressWarnings("unchecked")
    private static String stepSource(Object job) {
        StringBuilder source = new StringBuilder();
        for (Object step : (List<Object>) ((Map<String, Object>) job).getOrDefault("steps", List.of())) {
            Map<String, Object> fields = (Map<String, Object>) step;
            source.append(fields.getOrDefault("run", "")).append('\n');
            source.append(fields.getOrDefault("env", Map.of())).append('\n');
        }
        return source.toString();
    }

    @SuppressWarnings("unchecked")
    private static List<String> needsOf(String jobName) throws IOException {
        Object needs = ((Map<String, Object>) jobs().get(jobName)).get("needs");
        return needs instanceof String single ? List.of(single) : (List<String>) needs;
    }

    /**
     * The {@code mvn} command lines a job runs, with backslash continuations joined. Only a command position counts:
     * {@code generated} echoes a {@code mvn} line inside its diff message, and that is prose, not an invocation.
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
                    .filter(line -> MAVEN_INVOCATION.matcher(line).find())
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
