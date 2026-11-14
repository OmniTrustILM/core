package com.otilm.ai.controller;

import java.io.OutputStream;
import java.io.PrintStream;
import java.nio.file.Path;
import java.time.Duration;
import java.time.Instant;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.stream.Collectors;

/** Fixed controller entrypoint; no ingress daemon or caller-selected executable, URL or credential. */
public final class ControllerMain {
    private ControllerMain() {
    }

    public static void main(String[] arguments) {
        long started = System.nanoTime();
        System.setErr(new PrintStream(OutputStream.nullOutputStream()));
        var terminal = new AtomicBoolean();
        UUID correlation = UUID.randomUUID();
        Thread.setDefaultUncaughtExceptionHandler((thread, failure) -> {
            metadata(terminal, correlation, "UNKNOWN");
            Runtime.getRuntime().halt(1);
        });
        var guard = Executors
                .newSingleThreadScheduledExecutor(
                        Thread.ofPlatform().daemon().name("ai-controller-aggregate").factory());
        try {
            guard.schedule(() -> {
                metadata(terminal, correlation, "UNKNOWN");
                Runtime.getRuntime().halt(1);
            }, Math.max(1, TimeUnit.SECONDS.toNanos(120) - (System.nanoTime() - started)), TimeUnit.NANOSECONDS);
            if (arguments == null
                    || arguments.length != 3 && (arguments.length != 4 || !"cleanup".equals(arguments[3]))) {
                throw new ObservationFailure();
            }
            for (String option : new String[]{"_JAVA_OPTIONS", "JAVA_TOOL_OPTIONS", "JDK_JAVA_OPTIONS"}) {
                String value = System.getenv(option);
                if (value != null && !value.isBlank()) {
                    throw new ObservationFailure();
                }
            }
            UUID run = UUID.fromString(arguments[1]);
            UUID attempt = UUID.fromString(arguments[2]);
            if (!run.toString().equals(arguments[1]) || !attempt.toString().equals(arguments[2])) {
                throw new ObservationFailure();
            }
            var locator = new ControllerWire.Locator(correlation, run, attempt);
            var configuration = ControllerConfiguration.read(Path.of(arguments[0]));
            var profile = ControllerProfile.read(configuration.profileFile());
            if (arguments.length == 4) {
                executeCleanup(configuration, profile, locator, started);
            } else {
                execute(configuration, profile, locator, started);
            }
            metadata(terminal, correlation, "CLEANUP_RECORDED");
        } catch (Throwable unavailable) {
            metadata(terminal, correlation, "UNKNOWN");
            System.exit(1);
        } finally {
            // Keep the queued daemon cutoff if an unexpected non-daemon thread survives Main.
            guard.shutdown();
        }
    }

    static void execute(ControllerConfiguration configuration, ControllerProfile profile,
            ControllerWire.Locator locator) {
        execute(configuration, profile, locator, System.nanoTime());
    }

    static void execute(ControllerConfiguration configuration, ControllerProfile profile,
            ControllerWire.Locator locator, long started) {
        new Run(configuration, profile, locator, started).execute();
    }

    static void executeCleanup(ControllerConfiguration configuration, ControllerProfile profile,
            ControllerWire.Locator locator, long started) {
        new Run(configuration, profile, locator, started).resumeCleanup();
    }

    private static final class Run {
        private final long started;
        private final ControllerConfiguration configuration;
        private final ControllerProfile profile;
        private final ControllerWire.Locator locator;
        private final ControllerCoreClient core;
        private KubernetesApi api;
        private ControllerWire.Launch launch;
        private long runRevision;
        private long fence;
        private long observationSequence;
        private KubernetesApi.CreatedJob created;
        private KubernetesSnapshotVerifier.Pins pins;
        private List<KubernetesSnapshotVerifier.Pins> workloads = List.of();
        private final Set<String> startedPods = new HashSet<>();
        private boolean registered;
        private boolean gateAttempted;
        private boolean cleanupAttempted;

        private Run(ControllerConfiguration configuration, ControllerProfile profile, ControllerWire.Locator locator,
                long started) {
            this.started = started;
            this.configuration = configuration;
            this.profile = profile;
            this.locator = locator;
            core = new ControllerCoreClient(configuration);
        }

        private void execute() {
            try {
                launchAndFindPod();
                for (var workload : workloads) {
                    pins = workload;
                    releaseAndRegister();
                }
                registered = true;
                awaitFence();
                cleanup();
            } catch (Throwable unavailable) {
                if (!core.cleanupUncertain() && (api == null || !api.cleanupUncertain()) && launch != null
                        && !cleanupAttempted) {
                    try {
                        if (created == null) {
                            cleanupAttempted = true;
                            core.control(ControllerWire.ControlOperation.FENCE, locator, null, phase(true));
                        } else {
                            cleanup();
                        }
                    } catch (Throwable ignored) {
                        // A distinct bounded denial attempt is not a replay of the ambiguous operation.
                    }
                }
                throw new ObservationFailure();
            }
        }

        private void resumeCleanup() {
            phase(true);
            profile.requireRunnerDeadline();
            cleanupAttempted = true;
            var reply = core.resumeCleanup(locator, phase(true));
            if (reply.control().workloads().stream().anyMatch(pod -> !profile.cluster().equals(pod.cluster()))) {
                throw new ObservationFailure();
            }
            if (reply.done()) {
                return;
            }
            var control = reply.control();
            runRevision = control.runRevision();
            fence = control.fence();
            api = open(true);
            var job = KubernetesSnapshotVerifier.parse(api.job(profile.namespaceName(), profile.jobName()));
            created = new KubernetesApi.CreatedJob(control.jobUid().toString(),
                    KubernetesSnapshotVerifier.text(job.path("metadata"), "resourceVersion"));
            workloads = profile.findPods(api.pods(profile.namespaceName()), created.uid());
            if (workloads.isEmpty()) {
                throw new ObservationFailure();
            }
            pins = workloads.getFirst();
            workloads.forEach(workload -> startedPods.add(workload.podUid()));
            current(control, true);
            fencedCleanup(control);
        }

        private void launchAndFindPod() {
            profile.requireRunnerDeadline();
            launch = core.launch(locator, phase(false));
            runRevision = launch.runRevision();
            fence = launch.fence();
            profile.requireLaunch(launch);
            api = open(false);
            created = api.createJob(profile.namespaceName(), profile.jobName(), profile.job());
            known();
            while (pins == null) {
                api = open(false);
                workloads = profile.findPods(api.pods(profile.namespaceName()), created.uid());
                pins = workloads.isEmpty() ? null : workloads.getFirst();
                known();
                if (pins == null) {
                    pause(false);
                }
            }
        }

        private void releaseAndRegister() {
            api = open(false);
            KubernetesObserver.observe(api, pins, KubernetesSnapshotVerifier.Stage.GATED);
            known();
            var request = new ControllerWire.ObservationRequest(locator, UUID.fromString(pins.podUid()));
            var eligible = core.observe(ControllerWire.Operation.ELIGIBLE, request, phase(false));
            acknowledgement(eligible);
            api = open(false, eligible.validUntil());
            gateAttempted = true;
            api
                    .releaseGate(pins.namespaceName(), pins.podName(), pins.podUid(), eligible.podResourceVersion(),
                            pins.schedulingGate());
            known();
            awaitRunningPod();
            acknowledgement(core.observe(ControllerWire.Operation.REGISTER, request, phase(false)));
        }

        private void awaitRunningPod() {
            while (true) {
                api = open(false);
                var pod = KubernetesSnapshotVerifier.parse(api.pod(pins.namespaceName(), pins.podName()));
                if (!pins.podUid().equals(pod.path("metadata").path("uid").asText())) {
                    throw new ObservationFailure();
                }
                if ("Pending".equals(pod.path("status").path("phase").asText())) {
                    known();
                    pause(false);
                    continue;
                }
                KubernetesObserver.observe(api, pins, KubernetesSnapshotVerifier.Stage.RUNNING);
                known();
                startedPods.add(pins.podUid());
                break;
            }
        }

        private void awaitFence() {
            while (true) {
                var state = core.control(ControllerWire.ControlOperation.STATUS, locator, null, phase(false));
                current(state.control(), "FENCED".equals(state.attemptState()));
                if ("FENCED".equals(state.attemptState())) {
                    break;
                }
                pause(false);
            }
        }

        private void cleanup() {
            cleanupAttempted = true;
            try {
                fencedCleanup();
            } catch (Throwable unavailable) {
                if (!gateAttempted && pins != null) {
                    try {
                        removeNeverStartedGatedJob();
                    } catch (Throwable ignored) {
                        // Unknown physical cleanup retains the Core reservation; it cannot produce DONE.
                    }
                }
                throw new ObservationFailure();
            }
        }

        private void fencedCleanup() {
            fencedCleanup(core.control(ControllerWire.ControlOperation.FENCE, locator, null, phase(true)).control());
        }

        private void fencedCleanup(ControllerWire.Control control) {
            current(control, true);
            awaitTerminal();
            var terminal = core.control(ControllerWire.ControlOperation.TERMINAL, locator, control, phase(true));
            if (!terminal.control().equals(control) || terminal.validUntil() == null
                    || !terminal.validUntil().isAfter(Instant.now())) {
                throw new ObservationFailure();
            }
            api = open(true, terminal.validUntil());
            deleteKnownJob();
            awaitAbsence();
            var recorded = core.control(ControllerWire.ControlOperation.CLEANUP, locator, control, phase(true));
            if (!recorded.control().equals(control)) {
                throw new ObservationFailure();
            }
            phase(true);
        }

        private void awaitTerminal() {
            while (true) {
                boolean terminal = true;
                for (var workload : workloads) {
                    api = open(true);
                    var stage = startedPods.contains(workload.podUid())
                            ? KubernetesSnapshotVerifier.Stage.NOT_TERMINAL_YET
                            : KubernetesSnapshotVerifier.Stage.TERMINAL;
                    var observed = KubernetesObserver.observe(api, workload, stage);
                    known();
                    terminal &= observed.workload().stage() == KubernetesSnapshotVerifier.Stage.TERMINAL;
                }
                if (terminal) {
                    return;
                }
                pause(true);
            }
        }

        private void removeNeverStartedGatedJob() {
            api = open(true);
            var pod = KubernetesSnapshotVerifier.parse(api.pod(pins.namespaceName(), pins.podName()));
            if (!pins.podUid().equals(pod.path("metadata").path("uid").asText())
                    || !"Pending".equals(pod.path("status").path("phase").asText())) {
                throw new ObservationFailure();
            }
            for (String field : new String[]{
                    "containerStatuses",
                    "initContainerStatuses",
                    "ephemeralContainerStatuses"}) {
                var rows = pod.path("status").path(field);
                if (!rows.isMissingNode() && (!rows.isArray() || !rows.isEmpty())) {
                    throw new ObservationFailure();
                }
            }
            var observed = KubernetesObserver.observe(api, pins, KubernetesSnapshotVerifier.Stage.GATED);
            if (!observed
                    .workload()
                    .podResourceVersion()
                    .equals(KubernetesSnapshotVerifier.text(pod.path("metadata"), "resourceVersion"))) {
                throw new ObservationFailure();
            }
            deleteKnownJob();
            awaitAbsence();
            // Physical denial cleanup is not terminal equivalence, DONE or a capacity-release grant.
        }

        private void deleteKnownJob() {
            var job = KubernetesSnapshotVerifier.parse(api.job(profile.namespaceName(), profile.jobName()));
            var metadata = job.path("metadata");
            if (!created.uid().equals(metadata.path("uid").asText())
                    || !profile.namespaceName().equals(metadata.path("namespace").asText())
                    || !profile.jobName().equals(metadata.path("name").asText())
                    || !"batch/v1".equals(job.path("apiVersion").asText()) || !"Job".equals(job.path("kind").asText())
                    || !KubernetesSnapshotVerifier
                            .parse(pins.jobSpecJson().getBytes(java.nio.charset.StandardCharsets.UTF_8))
                            .equals(job.path("spec"))) {
                throw new ObservationFailure();
            }
            api
                    .deleteJob(profile.namespaceName(), profile.jobName(), created.uid(),
                            KubernetesSnapshotVerifier.text(metadata, "resourceVersion"));
            known();
        }

        private void awaitAbsence() {
            while (true) {
                api = open(true);
                boolean absent = api.jobAbsent(profile.namespaceName(), profile.jobName(), created.uid());
                byte[] listed = api.pods(profile.namespaceName());
                boolean ownedAbsent = profile.findPods(listed, created.uid()).isEmpty();
                for (var pod : KubernetesSnapshotVerifier.parse(listed).path("items")) {
                    if (workloads
                            .stream()
                            .anyMatch(workload -> workload.podUid().equals(pod.path("metadata").path("uid").asText())
                                    || workload.podName().equals(pod.path("metadata").path("name").asText()))) {
                        ownedAbsent = false;
                    }
                }
                if (absent && ownedAbsent) {
                    known();
                    break;
                }
                known();
                pause(true);
            }
            phase(true);
        }

        private void acknowledgement(ControllerWire.ObservationReply reply) {
            phase(false);
            if (!created.uid().equals(reply.jobUid().toString()) || reply.runRevision() <= runRevision
                    || reply.fence() != fence || reply.observationSequence() <= observationSequence
                    || !reply.validUntil().isAfter(Instant.now())) {
                throw new ObservationFailure();
            }
            runRevision = reply.runRevision();
            observationSequence = reply.observationSequence();
        }

        private void current(ControllerWire.Control control, boolean fenced) {
            if (created == null || pins == null || control.jobUid() == null
                    || !created.uid().equals(control.jobUid().toString())
                    || !control
                            .workloads()
                            .equals(workloads
                                    .stream()
                                    .map(workload -> new ControllerWire.Pod(profile.cluster(),
                                            UUID.fromString(workload.podUid())))
                                    .collect(Collectors.toSet()))
                    || control.runRevision() < runRevision || control.fence() < fence
                    || control.fence() > fence && control.runRevision() <= runRevision
                    || (fenced ? launch != null && control.fence() <= launch.fence() : control.fence() != fence)) {
                throw new ObservationFailure();
            }
            runRevision = control.runRevision();
            fence = control.fence();
        }

        private KubernetesApi open(boolean cleanup) {
            known();
            return configuration.kubernetes().open(phase(cleanup));
        }

        private KubernetesApi open(boolean cleanup, Instant evidenceUntil) {
            var budget = phase(cleanup);
            var evidence = Duration.between(Instant.now(), evidenceUntil);
            if (evidence.isNegative() || evidence.isZero()) {
                throw new ObservationFailure();
            }
            return configuration.kubernetes().open(evidence.compareTo(budget) < 0 ? evidence : budget);
        }

        private void known() {
            if (core.cleanupUncertain() || api != null && api.cleanupUncertain()) {
                throw new ObservationFailure();
            }
        }

        private Duration phase(boolean cleanup) {
            known();
            long remaining = TimeUnit.SECONDS.toNanos(cleanup ? 120 : 90) - (System.nanoTime() - started);
            if (launch != null && !cleanup) {
                Instant deadline = !registered ? launch.launchDeadline() : launch.maxDeadline();
                remaining = Math.min(remaining, Duration.between(Instant.now(), deadline).toNanos());
            }
            if (remaining <= 0 || Thread.currentThread().isInterrupted()) {
                throw new ObservationFailure();
            }
            return Duration.ofNanos(Math.min(remaining, TimeUnit.SECONDS.toNanos(5)));
        }

        private void pause(boolean cleanup) {
            long millis = Math.min(1000, phase(cleanup).toMillis());
            try {
                Thread.sleep(Math.max(1, millis));
            } catch (InterruptedException interrupted) {
                Thread.currentThread().interrupt();
                throw new ObservationFailure();
            }
            phase(cleanup);
        }
    }

    private static void metadata(AtomicBoolean terminal, UUID correlation, String code) {
        if (terminal.compareAndSet(false, true)) {
            System.out.println("phase=controller op=- code=" + code + " correlation=" + correlation);
        }
    }
}
