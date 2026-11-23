package com.otilm.ai.controller;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermissions;
import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.UUID;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.TimeUnit;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTimeoutPreemptively;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Maintained workflow on actual local HTTP/mTLS fixtures; synthetic Core replies are not real Core/native authority.
 */
class ControllerWorkflowTest {
    private static final ObjectMapper JSON = new ObjectMapper();
    private static final String JOB_UID = "736947e7-2778-4b40-8b0b-a514e319113c";
    private static final String POD_UID = "34adfc5b-55f9-4ffd-9b7a-b48eaaf0baf3";
    private static final String JOB = "ilm-ai-d00f5707e1ad41e09f21b66c74358c99";
    private static final String POD = JOB + "-abcde";
    private static final String SECOND_UID = "984a4caa-e002-4fe0-aee5-937ef7b2cfec";
    private static final String SECOND_NAME = JOB + "-second";
    private static final ControllerWire.Locator LOCATOR = new ControllerWire.Locator(
            UUID.fromString("a38cebd7-eafd-4cac-aed1-e1fcae264b85"),
            UUID.fromString("e7a0989e-4cd6-42d7-baf6-344caf843551"),
            UUID.fromString("d00f5707-e1ad-41e0-9f21-b66c74358c99"));
    @TempDir
    Path directory;

    @Test
    void maintainedFlowCreatesThenPersistsEligibleBeforeGateAndUsesFreshRegistrationAndFencedCleanup()
            throws Exception {
        try (var scenario = new Scenario(directory)) {
            assertDoesNotThrow(() -> ControllerMain.execute(scenario.configuration, scenario.profile, LOCATOR),
                    () -> scenario.trace + "; fixture=" + scenario.failure);
            assertTrue(scenario.deleted);
            assertTrue(scenario.trace.indexOf("core-eligible") < scenario.trace.indexOf("api-patch"));
            assertTrue(scenario.trace.indexOf("api-create") < scenario.trace.indexOf("core-eligible"));
            assertTrue(scenario.trace.indexOf("api-patch") < scenario.trace.indexOf("core-register"));
            assertTrue(scenario.trace.indexOf("core-fence") < scenario.trace.indexOf("core-terminal"));
            assertTrue(scenario.trace.indexOf("core-terminal") < scenario.trace.indexOf("api-delete"));
            assertTrue(scenario.trace.indexOf("api-delete") < scenario.trace.indexOf("core-cleanup"));
            for (String mutation : List
                    .of("api-create", "api-patch", "api-delete", "core-eligible", "core-register", "core-cleanup")) {
                assertEquals(1, scenario.trace.stream().filter(mutation::equals).count(), mutation);
            }
            assertNull(scenario.failure);
            assertTrue(scenario.core.authenticatedClients.get() >= 6);
        }
    }

    @Test
    void freshProcessResumesFencedCleanupWithoutLaunchingOrReleasingExecution() throws Exception {
        try (var scenario = new Scenario(directory)) {
            scenario.prepareResumption();
            var child = new ControllerMainTest();
            child.directory = directory;
            var result = child
                    .child(List
                            .of(scenario.configurationFile(directory).toString(), LOCATOR.runId().toString(),
                                    LOCATOR.attemptId().toString(), "cleanup"),
                            false);
            assertEquals(0, result.exit(), () -> scenario.trace + "; fixture=" + scenario.failure);
            assertFalse(scenario.trace.contains("core-launch"));
            assertFalse(scenario.trace.contains("api-create"));
            assertFalse(scenario.trace.contains("api-patch"));
            assertFalse(scenario.trace.contains("core-eligible"));
            assertFalse(scenario.trace.contains("core-register"));
            assertTrue(scenario.trace.contains("core-cleanup"));
            assertNull(scenario.failure);
        }
    }

    @Test
    void freshCleanupOfMultiplePodsUsesTheExactFullFootprintWithoutExecution() throws Exception {
        try (var scenario = new Scenario(directory)) {
            scenario.multiplePods = true;
            scenario.prepareResumption();
            assertDoesNotThrow(
                    () -> ControllerMain
                            .executeCleanup(scenario.configuration, scenario.profile, LOCATOR, System.nanoTime()),
                    () -> scenario.trace + "; fixture=" + scenario.failure);
            assertEquals(List.of("core-resume", "core-terminal", "core-cleanup"),
                    scenario.trace.stream().filter(value -> value.startsWith("core-")).toList());
            assertEquals(1, scenario.trace.stream().filter("api-delete"::equals).count());
            assertNull(scenario.failure);
        }
    }

    @Test
    void recordedCleanupReturnsTruthfullyWithoutAnyKubernetesAction() throws Exception {
        try (var scenario = new Scenario(directory)) {
            scenario.resumeDone = true;
            assertDoesNotThrow(() -> ControllerMain
                    .executeCleanup(scenario.configuration, scenario.profile, LOCATOR, System.nanoTime()));
            assertEquals(List.of("core-resume"), scenario.trace);
            assertEquals(0, scenario.api.requests.get());
            assertFalse(scenario.deleted);
        }
    }

    @Test
    void missingNativeEvidenceOrForeignResumeFootprintCannotDeleteOrRecordDone() throws Exception {
        for (String defect : List.of("absent", "missing-pods", "foreign", "rejected-terminal")) {
            try (var scenario = new Scenario(directory)) {
                scenario.prepareResumption();
                scenario.deleted = defect.equals("absent");
                scenario.hideOwnedPods = defect.equals("missing-pods");
                scenario.foreignResume = defect.equals("foreign");
                scenario.rejectResumeTerminal = defect.equals("rejected-terminal");
                assertThrows(ObservationFailure.class, () -> ControllerMain
                        .executeCleanup(scenario.configuration, scenario.profile, LOCATOR, System.nanoTime()));
                assertFalse(scenario.trace.contains("api-delete"));
                assertFalse(scenario.trace.contains("core-cleanup"));
                assertFalse(scenario.trace.contains("core-launch"));
                assertFalse(scenario.trace.contains("core-fence"));
                assertNull(scenario.failure);
            }
        }
    }

    @Test
    void cleanupResumptionCannotResetAnExpiredAggregateEntryBudget() throws Exception {
        try (var scenario = new Scenario(directory)) {
            long started = System.nanoTime() - TimeUnit.SECONDS.toNanos(120);
            assertThrows(ObservationFailure.class,
                    () -> ControllerMain.executeCleanup(scenario.configuration, scenario.profile, LOCATOR, started));
            assertEquals(0, scenario.core.requests.get());
            assertEquals(0, scenario.api.requests.get());
        }
    }

    @Test
    void distinctOwnedPodsRegisterAndShareOneFencedJobCleanup() throws Exception {
        try (var scenario = new Scenario(directory)) {
            scenario.multiplePods = true;
            assertDoesNotThrow(() -> ControllerMain.execute(scenario.configuration, scenario.profile, LOCATOR),
                    () -> scenario.trace + "; fixture=" + scenario.failure);
            for (String operation : List.of("core-eligible", "api-patch", "core-register")) {
                assertEquals(2, scenario.trace.stream().filter(operation::equals).count(), operation);
            }
            for (String operation : List
                    .of("api-create", "core-fence", "core-terminal", "api-delete", "core-cleanup")) {
                assertEquals(1, scenario.trace.stream().filter(operation::equals).count(), operation);
            }
            assertNull(scenario.failure);
        }
    }

    @Test
    void fencedStartedWorkWaitsForExactNativeTerminationBeforeOneDeleteAndCleanup() throws Exception {
        try (var scenario = new Scenario(directory)) {
            scenario.delayedTermination = true;
            assertTimeoutPreemptively(Duration.ofSeconds(8),
                    () -> assertDoesNotThrow(
                            () -> ControllerMain.execute(scenario.configuration, scenario.profile, LOCATOR),
                            () -> scenario.trace + "; fixture=" + scenario.failure));
            assertTrue(scenario.terminalJobReads >= 6);
            for (String operation : List.of("core-fence", "core-terminal", "api-delete", "core-cleanup")) {
                assertEquals(1, scenario.trace.stream().filter(operation::equals).count(), operation);
            }
            assertTrue(scenario.trace.indexOf("core-terminal") < scenario.trace.indexOf("api-delete"));
            assertNull(scenario.failure);
        }
    }

    @Test
    void nativeTerminationLandingOnTheObserverRereadContinuesAsBoundedProgress() throws Exception {
        try (var scenario = new Scenario(directory)) {
            scenario.delayedTermination = true;
            scenario.terminalTransitionRead = 4;
            assertTimeoutPreemptively(Duration.ofSeconds(8),
                    () -> assertDoesNotThrow(
                            () -> ControllerMain.execute(scenario.configuration, scenario.profile, LOCATOR),
                            () -> scenario.trace + "; fixture=" + scenario.failure));
            for (String operation : List.of("core-fence", "core-terminal", "api-delete", "core-cleanup")) {
                assertEquals(1, scenario.trace.stream().filter(operation::equals).count(), operation);
            }
            assertTrue(scenario.terminalJobReads >= 6);
            assertNull(scenario.failure);
        }
    }

    @Test
    void aRunnerRecipeWithAutomaticJobRetriesCannotContactCoreOrKubernetes() throws Exception {
        try (var scenario = new Scenario(directory)) {
            var recipe = scenario.recipe.deepCopy();
            ((ObjectNode) recipe.path("job").path("spec")).put("backoffLimit", 1);
            var file = Files.createTempFile(directory, "retry-profile-", ".json");
            Files.writeString(file, recipe.toString());
            Files.setPosixFilePermissions(file, PosixFilePermissions.fromString("rw-------"));
            var profile = ControllerProfile.read(file);
            assertThrows(ObservationFailure.class,
                    () -> ControllerMain.execute(scenario.configuration, profile, LOCATOR));
            assertTrue(scenario.trace.isEmpty(), scenario.trace::toString);
        }
    }

    @Test
    void profileDriftWhileWaitingCannotBeRetriedAsAStillRunningWorkload() throws Exception {
        try (var scenario = new Scenario(directory)) {
            scenario.delayedTermination = true;
            scenario.invalidWaitingPod = true;
            assertThrows(ObservationFailure.class,
                    () -> ControllerMain.execute(scenario.configuration, scenario.profile, LOCATOR));
            assertEquals(1, scenario.terminalJobReads);
            assertFalse(scenario.trace.contains("core-terminal"));
            assertFalse(scenario.trace.contains("api-delete"));
            assertFalse(scenario.trace.contains("core-cleanup"));
        }
    }

    @Test
    void freshCoreRevisionsCanAdvanceAcrossObservationsAndConcurrentClaims() throws Exception {
        try (var scenario = new Scenario(directory)) {
            scenario.eligibleRevision = 8;
            scenario.registerRevision = 11;
            scenario.statusRevision = 14;
            scenario.fenceRevision = 15;
            assertDoesNotThrow(() -> ControllerMain.execute(scenario.configuration, scenario.profile, LOCATOR),
                    scenario.trace::toString);
            assertTrue(scenario.trace.contains("core-cleanup"));
            assertNull(scenario.failure);
        }
    }

    @Test
    void anObservationAcknowledgementMustAdvanceRevisionBeforeReleasingTheGate() throws Exception {
        try (var scenario = new Scenario(directory)) {
            scenario.eligibleRevision = 7;
            assertThrows(ObservationFailure.class,
                    () -> ControllerMain.execute(scenario.configuration, scenario.profile, LOCATOR));
            assertFalse(scenario.trace.contains("api-patch"));
            assertFalse(scenario.trace.contains("core-register"));
            assertFalse(scenario.trace.contains("core-cleanup"));
        }
    }

    @Test
    void registrationMustAdvanceBothRevisionAndObservationSequenceBeforeStatusWork() throws Exception {
        for (boolean revision : new boolean[]{false, true}) {
            try (var scenario = new Scenario(directory)) {
                scenario.eligibleRevision = 8;
                scenario.registerRevision = revision ? 8 : 9;
                scenario.registerSequence = revision ? 2 : 1;
                assertThrows(ObservationFailure.class,
                        () -> ControllerMain.execute(scenario.configuration, scenario.profile, LOCATOR));
                assertTrue(scenario.trace.contains("core-register"), scenario.trace::toString);
                assertFalse(scenario.trace.contains("core-status"));
            }
        }
    }

    @Test
    void aStaleFenceTupleCannotAuthorizeTerminalObservationOrCleanupDone() throws Exception {
        try (var scenario = new Scenario(directory)) {
            scenario.eligibleRevision = 8;
            scenario.registerRevision = 9;
            scenario.statusRevision = 12;
            scenario.fenceRevision = 11;
            assertThrows(ObservationFailure.class,
                    () -> ControllerMain.execute(scenario.configuration, scenario.profile, LOCATOR));
            assertTrue(scenario.trace.contains("core-fence"), scenario.trace::toString);
            assertFalse(scenario.trace.contains("core-terminal"));
            assertFalse(scenario.trace.contains("core-cleanup"));
        }
    }

    @Test
    void mismatchedEligibleAcknowledgementNeverReleasesTheGateOrRegistersOrClaimsCleanupDone() throws Exception {
        try (var scenario = new Scenario(directory)) {
            scenario.badEligible = true;
            assertThrows(ObservationFailure.class,
                    () -> ControllerMain.execute(scenario.configuration, scenario.profile, LOCATOR));
            assertFalse(scenario.trace.contains("api-patch"));
            assertFalse(scenario.trace.contains("core-register"));
            assertFalse(scenario.trace.contains("core-cleanup"));
            assertTrue(scenario.trace.contains("core-fence"));
            assertTrue(scenario.deleted, scenario.trace::toString);
        }
    }

    @Test
    void unrelatedNamespacePodsDoNotPreventExactOwnedAbsenceCleanup() throws Exception {
        try (var scenario = new Scenario(directory)) {
            scenario.unrelatedPod = true;
            assertTimeoutPreemptively(Duration.ofSeconds(3),
                    () -> ControllerMain.execute(scenario.configuration, scenario.profile, LOCATOR));
            assertTrue(scenario.trace.contains("core-cleanup"));
            assertNull(scenario.failure);
        }
    }

    @Test
    void launchDeadlineDoesNotCancelAlreadyRegisteredWorkBeforeItsActualMaxDeadline() throws Exception {
        try (var scenario = new Scenario(directory)) {
            scenario.shortLaunchDeadline = true;
            scenario.pendingStatus = true;
            assertDoesNotThrow(() -> ControllerMain.execute(scenario.configuration, scenario.profile, LOCATOR),
                    scenario.trace::toString);
            assertTrue(scenario.trace.contains("core-cleanup"));
        }
    }

    @Test
    void expiredEntryBudgetCannotBeResetBeforeIdentityLoadingOrLaunch() throws Exception {
        try (var scenario = new Scenario(directory)) {
            long started = System.nanoTime() - TimeUnit.SECONDS.toNanos(120);
            assertThrows(ObservationFailure.class,
                    () -> ControllerMain.execute(scenario.configuration, scenario.profile, LOCATOR, started));
            assertTrue(scenario.trace.isEmpty());
            assertEquals(0, scenario.core.requests.get());
            assertEquals(0, scenario.api.requests.get());
        }
    }

    @Test
    void workCapExpiryFencesAndUsesOnlyTheRemainingAggregateCleanupTail() throws Exception {
        try (var scenario = new Scenario(directory)) {
            scenario.pendingStatus = true;
            long started = System.nanoTime() - TimeUnit.SECONDS.toNanos(89);
            assertThrows(ObservationFailure.class,
                    () -> ControllerMain.execute(scenario.configuration, scenario.profile, LOCATOR, started));
            assertTrue(scenario.trace.contains("core-fence"), scenario.trace::toString);
            assertTrue(scenario.trace.contains("core-cleanup"), scenario.trace::toString);
            assertEquals(1, scenario.trace.stream().filter("core-register"::equals).count());
        }
    }

    @Test
    void ambiguousCreationStillFencesTheAcceptedLaunchWithoutRetryOrFalseCleanup() throws Exception {
        try (var scenario = new Scenario(directory)) {
            scenario.ambiguousCreate = true;
            assertThrows(ObservationFailure.class,
                    () -> ControllerMain.execute(scenario.configuration, scenario.profile, LOCATOR));
            assertEquals(1, scenario.trace.stream().filter("api-create"::equals).count());
            assertEquals(1, scenario.trace.stream().filter("core-fence"::equals).count(), scenario.trace::toString);
            assertFalse(scenario.trace.contains("api-patch"));
            assertFalse(scenario.trace.contains("api-delete"));
            assertFalse(scenario.trace.contains("core-cleanup"));
        }
    }

    @Test
    void actualMainChildLoadsItsPrivateInputsAndEmitsOnlyMatchingCleanupMetadata() throws Exception {
        try (var scenario = new Scenario(directory)) {
            var entry = new ControllerMainTest();
            entry.directory = directory;
            var result = entry
                    .child(List
                            .of(scenario.configurationFile(directory).toString(), LOCATOR.runId().toString(),
                                    LOCATOR.attemptId().toString()),
                            false);
            assertEquals(0, result.exit(), scenario.trace::toString);
            assertTrue(result
                    .output()
                    .matches("phase=controller op=- code=CLEANUP_RECORDED correlation=[0-9a-f-]{36}\\R"));
            assertFalse(result.output().contains(directory.toString()));
            assertTrue(scenario.trace.contains("core-cleanup"));
            assertNull(scenario.failure);
        }
    }

    @Test
    void eligibleWindowCapsTheEntireFreshApiHandshakeBeforeGateHeadersCanBeSent() throws Exception {
        try (var scenario = new Scenario(directory)) {
            scenario.shortEligibleWindow = true;
            assertThrows(ObservationFailure.class,
                    () -> ControllerMain.execute(scenario.configuration, scenario.profile, LOCATOR));
            assertFalse(scenario.trace.contains("api-patch"), scenario.trace::toString);
            assertFalse(scenario.trace.contains("core-register"));
            assertTrue(scenario.trace.contains("core-fence"));
        }
    }

    @Test
    void terminalProofWindowCapsTheFreshJobReadBeforeDeleteCanBeSent() throws Exception {
        try (var scenario = new Scenario(directory)) {
            scenario.shortTerminalWindow = true;
            assertThrows(ObservationFailure.class,
                    () -> ControllerMain.execute(scenario.configuration, scenario.profile, LOCATOR));
            assertFalse(scenario.trace.contains("api-delete"), scenario.trace::toString);
            assertFalse(scenario.trace.contains("core-cleanup"));
        }
    }

    @Test
    void knownNeverStartedPhysicalDenialDoesNotDependOnAFenceAcknowledgementAndNeverClaimsDone() throws Exception {
        try (var scenario = new Scenario(directory)) {
            scenario.badEligible = true;
            scenario.denyFence = true;
            assertThrows(ObservationFailure.class,
                    () -> ControllerMain.execute(scenario.configuration, scenario.profile, LOCATOR));
            assertTrue(scenario.deleted, scenario.trace::toString);
            assertEquals(1, scenario.trace.stream().filter("core-fence"::equals).count());
            assertFalse(scenario.trace.contains("core-cleanup"));
        }
    }

    @Test
    void anyReportedContainerStatePreventsTheNeverStartedGatedCleanupExplanation() throws Exception {
        try (var scenario = new Scenario(directory)) {
            scenario.badEligible = true;
            scenario.gatedHasContainerState = true;
            assertThrows(ObservationFailure.class,
                    () -> ControllerMain.execute(scenario.configuration, scenario.profile, LOCATOR));
            assertFalse(scenario.deleted);
            assertFalse(scenario.trace.contains("core-cleanup"));
        }
    }

    private static final class Scenario implements AutoCloseable {
        private final KubernetesHttpsFixture core;
        private final KubernetesHttpsFixture api;
        private final ControllerConfiguration configuration;
        private final ControllerProfile profile;
        private final List<String> trace = new CopyOnWriteArrayList<>();
        private final ObjectNode recipe;
        private final ObjectNode job;
        private final ObjectNode pod;
        private volatile boolean resumeDone;
        private volatile boolean foreignResume;
        private volatile boolean hideOwnedPods;
        private volatile boolean rejectResumeTerminal;
        private volatile boolean multiplePods;
        private ObjectNode second;
        private final java.util.Set<String> releasedPods = new java.util.HashSet<>();
        private final java.util.Set<String> registeredPods = new java.util.HashSet<>();
        private long duplicateSequence;
        private volatile boolean delayedTermination;
        private volatile boolean invalidWaitingPod;
        private volatile boolean fenced;
        private int terminalJobReads;
        private int terminalTransitionRead = 5;
        private volatile boolean released;
        private volatile boolean registered;
        private volatile boolean deleted;
        private volatile boolean badEligible;
        private volatile boolean unrelatedPod;
        private volatile boolean shortLaunchDeadline;
        private volatile boolean pendingStatus;
        private volatile boolean ambiguousCreate;
        private volatile boolean shortEligibleWindow;
        private volatile boolean shortTerminalWindow;
        private volatile boolean terminalRecorded;
        private volatile boolean denyFence;
        private volatile boolean gatedHasContainerState;
        private long eligibleRevision = 8;
        private long registerRevision = 9;
        private long statusRevision = 10;
        private long fenceRevision = 10;
        private long registerSequence = 2;
        private int statusReads;
        private volatile Throwable failure;

        private Scenario(Path directory) throws Exception {
            core = new KubernetesHttpsFixture(200, new byte[]{'{', '}'});
            api = new KubernetesHttpsFixture(200, new byte[]{'{', '}'});
            core.requireClientAuthentication = true;
            var material = new ControllerCoreClientTest();
            material.directory = directory;
            var identity = material.configuration(core);
            Path apiCa = Files.createTempFile(directory, "api-ca-", ".pem");
            Files.writeString(apiCa, pem(api.ca.getEncoded()));
            Path profileFile = Files.createTempFile(directory, "recipe-", ".json");
            Files.writeString(profileFile, ControllerProfileTest.PROFILE);
            Files.setPosixFilePermissions(profileFile, PosixFilePermissions.fromString("rw-------"));
            profile = ControllerProfile.read(profileFile);
            configuration = new ControllerConfiguration(identity.core(), identity.certificateFile(),
                    identity.privateKeyFile(), identity.serverCaFile(),
                    new KubernetesConfiguration(api.endpoint(), apiCa, identity.kubernetes().tokenFile()), profileFile);
            recipe = (ObjectNode) JSON.readTree(ControllerProfileTest.PROFILE);
            job = ((ObjectNode) recipe.path("job")).deepCopy();
            ((ObjectNode) job.get("metadata")).put("uid", JOB_UID).put("resourceVersion", "job-rv-1");
            pod = object("v1", "Pod", POD, POD_UID, true);
            ((ObjectNode) pod.get("metadata")).put("resourceVersion", "pod-rv-1");
            ((ObjectNode) pod.get("metadata")).set("labels", recipe.path("podMetadata").path("labels"));
            ((ObjectNode) pod.get("metadata"))
                    .putArray("ownerReferences")
                    .addObject()
                    .put("apiVersion", "batch/v1")
                    .put("kind", "Job")
                    .put("name", JOB)
                    .put("uid", JOB_UID)
                    .put("controller", true);
            pod.set("spec", recipe.path("podSpec").deepCopy());
            pod.putObject("status").put("phase", "Pending");
            second = pod.deepCopy();
            ((ObjectNode) second.path("metadata")).put("name", SECOND_NAME).put("uid", SECOND_UID);
            core.responder = request -> response(() -> core(request));
            api.responder = request -> response(() -> api(request));
        }

        private void prepareResumption() {
            released = true;
            registered = true;
            fenced = true;
            for (var target : multiplePods ? List.of(pod, second) : List.of(pod)) {
                String uid = target.path("metadata").path("uid").textValue();
                releasedPods.add(uid);
                registeredPods.add(uid);
                ((ObjectNode) target.path("spec")).remove("schedulingGates");
                ((ObjectNode) target.path("spec")).put("nodeName", "node-one");
            }
        }

        private KubernetesHttpsFixture.Reply core(KubernetesHttpsFixture.Request request) throws Exception {
            assertNull(core.authorization.get());
            assertEquals("POST", request.method());
            var body = JSON.readTree(request.body());
            String kind = body.path("kind").asText();
            ObjectNode reply;
            if (kind.equals("launch-reconcile")) {
                trace.add("core-launch");
                reply = (ObjectNode) JSON.readTree(ControllerWireTest.BINDING);
                reply
                        .put("launchDeadline", Instant.now().plusSeconds(shortLaunchDeadline ? 1 : 60).toString())
                        .put("maxDeadline", Instant.now().plusSeconds(110).toString());
            } else if (kind.equals("workload-eligible") || kind.equals("workload-register")) {
                trace.add(kind.equals("workload-eligible") ? "core-eligible" : "core-register");
                boolean registration = kind.equals("workload-register");
                if (registration) {
                    registeredPods.add(body.path("podUid").textValue());
                }
                registered = registration && (!multiplePods || registeredPods.size() == 2);
                updateStatus();
                reply = binding(kind.equals("workload-eligible") ? "workload-eligible" : "workload-registered",
                        registered ? registerRevision : eligibleRevision, 3);
                if (multiplePods) {
                    reply.put("runRevision", 7 + ++duplicateSequence);
                }
                reply
                        .put("podUid", badEligible ? UUID.randomUUID().toString() : body.path("podUid").textValue())
                        .put("jobUid", JOB_UID)
                        .put("podResourceVersion",
                                releasedPods.contains(body.path("podUid").asText()) ? "pod-rv-2" : "pod-rv-1")
                        .put("observationSequence",
                                multiplePods ? duplicateSequence : registered ? registerSequence : 1)
                        .put("validUntil",
                                (shortEligibleWindow && !registered
                                        ? Instant.now().plusMillis(300)
                                        : Instant.now().plusSeconds(20)).toString());
                if (shortEligibleWindow && !registered) {
                    api.handshakeDelayMillis = 600;
                }
            } else {
                String responseKind = switch (kind) {
                    case "cleanup-resume" -> resumeDone ? "cleanup-recorded" : "cleanup-required";
                    case "workload-status" -> "workload-status";
                    case "cleanup-request" -> "cleanup-required";
                    case "cleanup-terminal-status" -> "cleanup-terminal-observed";
                    case "cleanup-reconcile" -> "cleanup-recorded";
                    default -> throw new AssertionError("Unexpected synthetic Core operation");
                };
                trace.add(switch (kind) {
                    case "cleanup-resume" -> "core-resume";
                    case "workload-status" -> "core-status";
                    case "cleanup-request" -> "core-fence";
                    case "cleanup-terminal-status" -> "core-terminal";
                    default -> "core-cleanup";
                });
                if (kind.equals("cleanup-request")) {
                    fenced = true;
                    api.handshakeDelayMillis = 0;
                    if (denyFence) {
                        return new KubernetesHttpsFixture.Reply(403, new byte[]{'{', '}'});
                    }
                }
                if (kind.equals("cleanup-terminal-status") && rejectResumeTerminal) {
                    return new KubernetesHttpsFixture.Reply(403, new byte[]{'{', '}'});
                }
                if (kind.equals("cleanup-reconcile")) {
                    assertTrue(deleted);
                }
                if (kind.equals("cleanup-terminal-status") || kind.equals("cleanup-reconcile")) {
                    assertEquals(multiplePods ? 7 + duplicateSequence + 1 : fenceRevision,
                            body.path("runRevision").longValue());
                    assertEquals(4, body.path("fence").longValue());
                    assertEquals(JOB_UID, body.path("jobUid").textValue());
                    assertEquals(multiplePods ? 2 : 1, body.path("workloads").size());
                    assertEquals("lab", body.path("workloads").get(0).path("cluster").textValue());
                    assertEquals(POD_UID, body.path("workloads").get(0).path("podUid").textValue());
                }
                boolean pending = kind.equals("workload-status") && pendingStatus && statusReads++ == 0;
                reply = binding(responseKind,
                        kind.equals("workload-status") ? (pending ? registerRevision : statusRevision) : fenceRevision,
                        pending ? 3 : 4).put("jobUid", JOB_UID);
                reply.putArray("workloads").addObject().put("cluster", "lab").put("podUid", POD_UID);
                if (multiplePods) {
                    ((com.fasterxml.jackson.databind.node.ArrayNode) reply.path("workloads"))
                            .addObject()
                            .put("cluster", "lab")
                            .put("podUid", SECOND_UID);
                    reply.put("runRevision", 7 + duplicateSequence + 1);
                }
                if (kind.equals("cleanup-resume") && foreignResume) {
                    ((ObjectNode) reply.path("workloads").get(0)).put("cluster", "foreign-cluster");
                }
                if (kind.equals("workload-status")) {
                    reply
                            .put("runState", pending ? "RUNNING" : "CANCELLED")
                            .put("attemptState", pending ? "CLAIMED" : "FENCED");
                }
                if (kind.equals("cleanup-terminal-status")) {
                    terminalRecorded = true;
                    reply
                            .put("validUntil",
                                    (shortTerminalWindow
                                            ? Instant.now().plusMillis(300)
                                            : Instant.now().plusSeconds(20)).toString());
                }
            }
            reply.put("correlationId", body.path("correlationId").textValue());
            return new KubernetesHttpsFixture.Reply(200, JSON.writeValueAsBytes(reply));
        }

        private Path configurationFile(Path directory) throws Exception {
            var root = JSON
                    .createObjectNode()
                    .put("version", 1)
                    .put("profileFile", configuration.profileFile().toString());
            root
                    .putObject("core")
                    .put("origin", configuration.core().origin().toString())
                    .put("address", configuration.core().address().getHostAddress())
                    .put("certificateFile", configuration.certificateFile().toString())
                    .put("privateKeyFile", configuration.privateKeyFile().toString())
                    .put("serverCaFile", configuration.serverCaFile().toString());
            root
                    .putObject("kubernetes")
                    .put("origin", configuration.kubernetes().endpoint().origin().toString())
                    .put("address", configuration.kubernetes().endpoint().address().getHostAddress())
                    .put("serverCaFile", configuration.kubernetes().serverCaFile().toString())
                    .put("tokenFile", configuration.kubernetes().tokenFile().toString());
            Path file = Files.createTempFile(directory, "main-config-", ".json");
            Files.write(file, JSON.writeValueAsBytes(root));
            Files.setPosixFilePermissions(file, PosixFilePermissions.fromString("rw-------"));
            return file;
        }

        private KubernetesHttpsFixture.Reply api(KubernetesHttpsFixture.Request request) throws Exception {
            String path = request.path();
            if (request.method().equals("POST")) {
                trace.add("api-create");
                assertEquals("/apis/batch/v1/namespaces/runtime/jobs", path);
                assertEquals(JSON.readTree(profile.job()), JSON.readTree(request.body()));
                if (ambiguousCreate) {
                    return new KubernetesHttpsFixture.Reply(503, new byte[]{'{', '}'});
                }
                return new KubernetesHttpsFixture.Reply(201, JSON.writeValueAsBytes(job));
            }
            if (request.method().equals("PATCH")) {
                trace.add("api-patch");
                assertTrue(trace.contains("core-eligible"));
                var patch = JSON.readTree(request.body());
                var target = path.endsWith("/" + SECOND_NAME) ? second : pod;
                String targetUid = target.path("metadata").path("uid").textValue();
                assertEquals(targetUid, patch.get(0).path("value").textValue());
                assertEquals(target.path("metadata").path("resourceVersion").textValue(),
                        patch.get(1).path("value").textValue());
                assertEquals(target.path("spec").path("schedulingGates").get(0).path("name").textValue(),
                        patch.get(2).path("value").textValue());
                released = true;
                releasedPods.add(targetUid);
                ((ObjectNode) target.get("metadata")).put("resourceVersion", "pod-rv-2");
                ((ObjectNode) target.get("spec")).remove("schedulingGates");
                ((ObjectNode) target.get("spec")).put("nodeName", "node-one");
                updateStatus();
                return new KubernetesHttpsFixture.Reply(200, JSON.writeValueAsBytes(target));
            }
            if (request.method().equals("DELETE")) {
                trace.add("api-delete");
                assertTrue(trace.contains("core-fence") || trace.contains("core-resume"));
                if (!trace.contains("core-terminal")) {
                    assertFalse(released);
                    assertEquals("Pending", pod.path("status").path("phase").textValue());
                    assertFalse(pod.path("spec").has("nodeName"));
                }
                var options = JSON.readTree(request.body());
                assertEquals(JOB_UID, options.path("preconditions").path("uid").textValue());
                assertEquals(job.path("metadata").path("resourceVersion").textValue(),
                        options.path("preconditions").path("resourceVersion").textValue());
                assertEquals("Foreground", options.path("propagationPolicy").textValue());
                assertFalse(options.has("gracePeriodSeconds"));
                deleted = true;
                var status = JSON
                        .createObjectNode()
                        .put("apiVersion", "v1")
                        .put("kind", "Status")
                        .put("status", "Success");
                status
                        .putObject("details")
                        .put("name", JOB)
                        .put("uid", JOB_UID)
                        .put("kind", "jobs")
                        .put("group", "batch");
                return new KubernetesHttpsFixture.Reply(200, JSON.writeValueAsBytes(status));
            }
            assertEquals("GET", request.method());
            if (gatedHasContainerState && !released) {
                ((ObjectNode) pod.path("status"))
                        .putArray("containerStatuses")
                        .addObject()
                        .put("name", "runner")
                        .putObject("state")
                        .putObject("running");
            }
            ObjectNode result;
            if (fenced && path.endsWith("/jobs/" + JOB)) {
                terminalJobReads++;
                updateStatus();
            }
            if (path.endsWith("/pods")) {
                result = JSON.createObjectNode().put("apiVersion", "v1").put("kind", "PodList");
                result.putObject("metadata").put("resourceVersion", "list-rv");
                var list = result.putArray("items");
                if (!deleted && !hideOwnedPods) {
                    updateStatus();
                    list.add(pod);
                    if (multiplePods) {
                        list.add(second);
                    }
                }
                if (unrelatedPod) {
                    list
                            .add(object("v1", "Pod", "another-owned-workload", "ad3abe26-09ca-4a8d-8d27-e195d9527f53",
                                    true));
                }
            } else if (path.endsWith("/jobs/" + JOB)) {
                if (shortTerminalWindow && terminalRecorded && !deleted) {
                    Thread.sleep(600);
                }
                if (deleted) {
                    result = JSON
                            .createObjectNode()
                            .put("apiVersion", "v1")
                            .put("kind", "Status")
                            .put("reason", "NotFound")
                            .put("code", 404);
                    result.putObject("details").put("name", JOB).put("kind", "jobs").put("group", "batch");
                    return new KubernetesHttpsFixture.Reply(404, JSON.writeValueAsBytes(result));
                }
                result = job;
            } else if (multiplePods && path.endsWith("/pods/" + SECOND_NAME)) {
                updateStatus();
                result = second;
            } else if (path.endsWith("/pods/" + POD)) {
                updateStatus();
                result = pod;
            } else if (path.endsWith("/serviceaccounts/runner")) {
                result = object("v1", "ServiceAccount", "runner",
                        recipe.path("pins").path("serviceAccountUid").textValue(), true);
            } else if (path.endsWith("/namespaces/runtime")) {
                result = object("v1", "Namespace", "runtime", recipe.path("pins").path("namespaceUid").textValue(),
                        false);
            } else if (path.endsWith("/runtimeclasses/ilm-runsc")) {
                result = object("node.k8s.io/v1", "RuntimeClass", "ilm-runsc",
                        recipe.path("runtime").path("uid").textValue(), false);
                result.put("handler", "runsc");
            } else {
                throw new AssertionError("Unexpected synthetic Kubernetes path");
            }
            return new KubernetesHttpsFixture.Reply(200, JSON.writeValueAsBytes(result));
        }

        private void updateStatus() {
            updateStatus(pod);
            if (multiplePods) {
                updateStatus(second);
            }
        }

        private void updateStatus(ObjectNode target) {
            String containerIdentity = "containerd://" + (target == second ? "e" : "d").repeat(64);
            if (releasedPods.contains(target.path("metadata").path("uid").asText())) {
                boolean terminated = registered && (!delayedTermination || terminalJobReads >= terminalTransitionRead);
                if (fenced && invalidWaitingPod) {
                    ((ObjectNode) target.path("spec")).put("hostPID", true);
                }
                var status = target.putObject("status").put("phase", terminated ? "Succeeded" : "Running");
                var row = status
                        .putArray("containerStatuses")
                        .addObject()
                        .put("name", "runner")
                        .put("imageID", "containerd://sha256:" + "c".repeat(64))
                        .put("containerID", containerIdentity)
                        .put("restartCount", 0)
                        .put("ready", !registered)
                        .put("started", true);
                if (terminated) {
                    row
                            .putObject("state")
                            .putObject("terminated")
                            .put("exitCode", 0)
                            .put("containerID", containerIdentity)
                            .put("finishedAt", "2026-11-06T00:00:00Z");
                    job
                            .putObject("status")
                            .putArray("conditions")
                            .addObject()
                            .put("type", "Complete")
                            .put("status", "True");
                } else {
                    row.putObject("state").putObject("running").put("startedAt", "2026-11-06T00:00:00Z");
                }
            }
        }

        private ObjectNode binding(String kind, long revision, long fence) {
            return JSON
                    .createObjectNode()
                    .put("version", 1)
                    .put("kind", kind)
                    .put("runId", LOCATOR.runId().toString())
                    .put("attemptId", LOCATOR.attemptId().toString())
                    .put("runRevision", revision)
                    .put("fence", fence);
        }

        private KubernetesHttpsFixture.Reply response(Reply action) {
            try {
                return action.get();
            } catch (Throwable invalid) {
                failure = invalid;
                return new KubernetesHttpsFixture.Reply(500, new byte[]{'{', '}'});
            }
        }

        private static ObjectNode object(String version, String kind, String name, String uid, boolean namespaced) {
            var value = JSON.createObjectNode().put("apiVersion", version).put("kind", kind);
            var metadata = value.putObject("metadata").put("name", name).put("uid", uid).put("resourceVersion", "rv-1");
            if (namespaced) {
                metadata.put("namespace", "runtime");
            }
            return value;
        }

        private static String pem(byte[] certificate) {
            return "-----BEGIN CERTIFICATE-----\n"
                    + java.util.Base64.getMimeEncoder(64, new byte[]{'\n'}).encodeToString(certificate)
                    + "\n-----END CERTIFICATE-----\n";
        }

        @Override
        public void close() throws Exception {
            core.close();
            api.close();
        }

        private interface Reply {
            KubernetesHttpsFixture.Reply get() throws Exception;
        }
    }
}
