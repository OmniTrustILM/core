package com.otilm.core.service.ai;

import com.fasterxml.jackson.databind.node.ObjectNode;
import com.otilm.ai.controller.ControllerWire;
import com.otilm.core.model.ai.AiRuntimeState;
import com.otilm.core.security.ai.AiRuntimeControllerAuthority;
import com.otilm.core.security.ai.RuntimePeer;
import com.otilm.core.security.ai.RuntimePeerRole;
import com.otilm.core.security.ai.RuntimeProxyCertificateClaims;
import com.otilm.core.security.ai.RuntimeProxyTransport;
import com.otilm.core.serialization.ObjectMapperFactory;
import com.otilm.core.service.writer.ai.AiRuntimeCleanupWriter;
import java.io.ByteArrayInputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermissions;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicLong;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.springframework.beans.factory.support.StaticListableBeanFactory;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anySet;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.mockStatic;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

/** Actual authenticated API/proof lifecycle with mocked DB/native-peer boundaries, not deployed authority. */
class AiRuntimeControllerServiceTest {
    private static final UUID RUN = UUID.fromString("e7a0989e-4cd6-42d7-baf6-344caf843551");
    private static final UUID ATTEMPT = UUID.fromString("d00f5707-e1ad-41e0-9f21-b66c74358c99");
    private static final UUID JOB = UUID.fromString("736947e7-2778-4b40-8b0b-a514e319113c");
    private static final UUID POD = UUID.fromString("34adfc5b-55f9-4ffd-9b7a-b48eaaf0baf3");
    private static final UUID SECOND_POD = UUID.fromString("1e23059f-bb4e-4da9-810a-f07f50580170");
    private static final String JOB_NAME = "ilm-ai-d00f5707e1ad41e09f21b66c74358c99";
    private static final String POD_NAME = JOB_NAME + "-one";
    private static final String SECOND_POD_NAME = JOB_NAME + "-two";
    private static final ControllerWire.Locator LOCATOR = new ControllerWire.Locator(UUID.randomUUID(), RUN, ATTEMPT);
    private static final ControllerWire.Control EXPECTED = new ControllerWire.Control(LOCATOR, 10, 4, JOB,
            Set.of(new ControllerWire.Pod("lab", POD)));
    @TempDir
    Path directory;

    @ParameterizedTest
    @ValueSource(booleans = {false, true})
    void completesOwnedCleanup_whenFeatureAdmissionHasEitherState(boolean featureEnabled) throws Exception {
        // given
        try (var fixture = new Fixture(directory, featureEnabled); var peer = mockStatic(RuntimeProxyTransport.class)) {
            peer.when(RuntimeProxyTransport::currentWorkloadPeer).thenReturn(Optional.of(fixture.peer));

            // when
            org.springframework.http.ResponseEntity<byte[]> terminalReply = fixture.terminal();

            // then
            verifyNoInteractions(fixture.cleanup);
            verify(fixture.kernel, never()).observe(any(), any());
            assertThat(terminalReply.getStatusCode().value()).isEqualTo(200);
            assertThat(fixture.api.requests.get()).isGreaterThanOrEqualTo(11);
            verifyNoInteractions(fixture.cleanup);
            fixture.absent = true;
            assertThat(fixture.complete().getStatusCode().value()).isEqualTo(200);
            assertThat(fixture.absenceNamespaceReads).hasValue(2);
            assertThat(fixture.complete().getStatusCode().value()).isEqualTo(403);
            verify(fixture.cleanup, times(1)).complete(any(), anyString(), anySet(), any());
            assertThat(fixture.api.failure.get()).isNull();
        }
    }

    @ParameterizedTest
    @ValueSource(booleans = {false, true})
    void freshControllerCanResumeOnlyPersistedFencedCleanupWhenAdmissionIsDisabledOrEnabled(boolean enabled)
            throws Exception {
        try (var fixture = new Fixture(directory, enabled); var peer = mockStatic(RuntimeProxyTransport.class)) {
            peer.when(RuntimeProxyTransport::currentWorkloadPeer).thenReturn(Optional.of(fixture.peer));
            var body = new String(ControllerWire.controlRequest(ControllerWire.ControlOperation.STATUS, LOCATOR, null),
                    StandardCharsets.UTF_8).replace("workload-status", "cleanup-resume");
            var response = fixture.service.status(new ByteArrayInputStream(body.getBytes(StandardCharsets.UTF_8)));
            assertThat(response.getStatusCode().value()).isEqualTo(200);
            assertThat(ControllerWire
                    .readControlReply(response.getBody(), ControllerWire.ControlOperation.FENCE, LOCATOR)
                    .control()).isEqualTo(EXPECTED);
            assertThat(fixture.api.requests).hasValue(0);
            verify(fixture.kernel, never()).invalidate(any(), any());
            verify(fixture.kernel, never()).observe(any(), any());
            verifyNoInteractions(fixture.cleanup);
        }
    }

    @Test
    void recordedCleanupResumesTruthfullyWithoutNativeOrWriterWork() throws Exception {
        try (var fixture = new Fixture(directory, false); var peer = mockStatic(RuntimeProxyTransport.class)) {
            peer.when(RuntimeProxyTransport::currentWorkloadPeer).thenReturn(Optional.of(fixture.peer));
            fixture.cleanupState(AiRuntimeState.CleanupState.DONE);
            var response = fixture.resume();
            assertThat(response.getStatusCode().value()).isEqualTo(200);
            assertThat(ControllerWire.readCleanupResumeReply(response.getBody(), LOCATOR).done()).isTrue();
            assertThat(fixture.api.requests).hasValue(0);
            verify(fixture.kernel, never()).invalidate(any(), any());
            verify(fixture.kernel, never()).observe(any(), any());
            verifyNoInteractions(fixture.cleanup);
        }
    }

    @ParameterizedTest
    @ValueSource(strings = {"launching", "none", "no-job", "no-pods", "foreign-locator", "stale-epoch"})
    void resumptionCannotManufactureMissingBindingsOrAdvanceAStaleCleanupTuple(String defect) throws Exception {
        try (var fixture = new Fixture(directory, false); var peer = mockStatic(RuntimeProxyTransport.class)) {
            peer.when(RuntimeProxyTransport::currentWorkloadPeer).thenReturn(Optional.of(fixture.peer));
            var locator = LOCATOR;
            if (defect.equals("launching")) {
                fixture.currentRun.set(fixture.queued());
            } else if (defect.equals("none")) {
                fixture.cleanupState(AiRuntimeState.CleanupState.NONE);
            } else if (defect.equals("no-job") || defect.equals("no-pods")) {
                fixture.incompleteBinding(defect.equals("no-job"));
            } else if (defect.equals("foreign-locator")) {
                locator = new ControllerWire.Locator(LOCATOR.correlationId(), LOCATOR.runId(), UUID.randomUUID());
            }
            var response = fixture.service
                    .status(new ByteArrayInputStream(ControllerWire.cleanupResumeRequest(locator)));
            if (defect.equals("stale-epoch")) {
                assertThat(response.getStatusCode().value()).isEqualTo(200);
                var stale = new ControllerWire.Control(LOCATOR, EXPECTED.runRevision() + 1, EXPECTED.fence(), JOB,
                        EXPECTED.workloads());
                response = fixture.terminal(stale);
            }
            assertThat(response.getStatusCode().value())
                    .isEqualTo(defect.equals("foreign-locator") || defect.equals("stale-epoch") ? 503 : 403);
            assertThat(fixture.api.requests).hasValue(0);
            verify(fixture.kernel, never()).invalidate(any(), any());
            verify(fixture.kernel, never()).observe(any(), any());
            verifyNoInteractions(fixture.cleanup);
        }
    }

    @Test
    void resumptionClearsAnyOldPrivateProofAndAbsenceCannotRecreateIt() throws Exception {
        try (var fixture = new Fixture(directory, false); var peer = mockStatic(RuntimeProxyTransport.class)) {
            peer.when(RuntimeProxyTransport::currentWorkloadPeer).thenReturn(Optional.of(fixture.peer));
            assertThat(fixture.terminal().getStatusCode().value()).isEqualTo(200);
            assertThat(fixture.resume().getStatusCode().value()).isEqualTo(200);
            int requests = fixture.api.requests.get();
            fixture.absent = true;
            assertThat(fixture.complete().getStatusCode().value()).isEqualTo(403);
            assertThat(fixture.api.requests).hasValue(requests);
            verifyNoInteractions(fixture.cleanup);
        }
    }

    @Test
    void reportsOwnedStatus_whenNewExecutionIsDisabled() throws Exception {
        // given
        try (var fixture = new Fixture(directory, false); var peer = mockStatic(RuntimeProxyTransport.class)) {
            peer.when(RuntimeProxyTransport::currentWorkloadPeer).thenReturn(Optional.of(fixture.peer));

            // when
            var response = fixture.service
                    .status(new ByteArrayInputStream(
                            ControllerWire.controlRequest(ControllerWire.ControlOperation.STATUS, LOCATOR, null)));

            // then
            assertThat(response.getStatusCode().value()).isEqualTo(200);
            var reply = ControllerWire
                    .readControlReply(response.getBody(), ControllerWire.ControlOperation.STATUS, LOCATOR);
            assertThat(reply.runState()).isEqualTo("CANCELLED");
            assertThat(reply.attemptState()).isEqualTo("FENCED");
            verify(fixture.authority).requireCurrent(any(), any());
            verify(fixture.kernel, never()).observe(any(), any());
            verify(fixture.kernel, never()).invalidate(any(), any());
            verifyNoInteractions(fixture.cleanup);
        }
    }

    @Test
    void fencesOwnedAttempt_whenNewExecutionIsDisabled() throws Exception {
        // given
        try (var fixture = new Fixture(directory, false); var peer = mockStatic(RuntimeProxyTransport.class)) {
            peer.when(RuntimeProxyTransport::currentWorkloadPeer).thenReturn(Optional.of(fixture.peer));
            fixture.currentRun.set(fixture.queued());
            when(fixture.kernel.invalidate(any(), any())).thenAnswer(call -> {
                fixture.currentRun.set(fixture.snapshot());
                return AiRuntimeState.Transition.empty(AiRuntimeState.Status.APPLIED);
            });

            // when
            var response = fixture.service
                    .cleanup(new ByteArrayInputStream(
                            ControllerWire.controlRequest(ControllerWire.ControlOperation.FENCE, LOCATOR, null)));

            // then
            assertThat(response.getStatusCode().value()).isEqualTo(200);
            var reply = ControllerWire
                    .readControlReply(response.getBody(), ControllerWire.ControlOperation.FENCE, LOCATOR);
            assertThat(reply.control().fence()).isEqualTo(4);
            assertThat(reply.control().jobUid()).isEqualTo(JOB);
            verify(fixture.authority).requireCurrent(any(), any());
            verify(fixture.kernel).invalidate(any(), any());
            verify(fixture.kernel, never()).observe(any(), any());
            verifyNoInteractions(fixture.cleanup);
        }
    }

    @ParameterizedTest
    @ValueSource(longs = {-1, 30_000_000_000L})
    void reversedOrExactlyExpiredPrivateMonotonicProofCannotReachTheCleanupWriter(long elapsed) throws Exception {
        try (var fixture = new Fixture(directory); var peer = mockStatic(RuntimeProxyTransport.class)) {
            peer.when(RuntimeProxyTransport::currentWorkloadPeer).thenReturn(Optional.of(fixture.peer));
            assertThat(fixture.terminal().getStatusCode().value()).isEqualTo(200);
            fixture.nanos.set(elapsed);
            fixture.absent = true;
            assertThat(fixture.complete().getStatusCode().value()).isEqualTo(403);
            assertThat(fixture.absenceNamespaceReads).hasValue(0);
            verifyNoInteractions(fixture.cleanup);
        }
    }

    @ParameterizedTest
    @ValueSource(ints = {1, 2})
    void aRecreatedNamespaceBeforeOrAfterOwnedAbsenceCannotReleaseTheReservation(int changedRead) throws Exception {
        try (var fixture = new Fixture(directory); var peer = mockStatic(RuntimeProxyTransport.class)) {
            peer.when(RuntimeProxyTransport::currentWorkloadPeer).thenReturn(Optional.of(fixture.peer));
            assertThat(fixture.terminal().getStatusCode().value()).isEqualTo(200);
            fixture.absent = true;
            fixture.changedNamespaceRead = changedRead;
            assertThat(fixture.complete().getStatusCode().value()).isEqualTo(403);
            verifyNoInteractions(fixture.cleanup);
        }
    }

    @ParameterizedTest
    @ValueSource(strings = {"duplicate", "trailing", "utf16"})
    void ambiguousNamespaceWireCannotSatisfyTheIndependentAbsenceBinding(String defect) throws Exception {
        try (var fixture = new Fixture(directory); var peer = mockStatic(RuntimeProxyTransport.class)) {
            peer.when(RuntimeProxyTransport::currentWorkloadPeer).thenReturn(Optional.of(fixture.peer));
            assertThat(fixture.terminal().getStatusCode().value()).isEqualTo(200);
            fixture.absent = true;
            fixture.namespaceDefect = defect;
            assertThat(fixture.complete().getStatusCode().is2xxSuccessful()).isFalse();
            verifyNoInteractions(fixture.cleanup);
        }
    }

    @Test
    void qualifiedKubernetesAnnotationNamesUseTheKubernetesMapperWithoutDroppingFields() throws Exception {
        try (var fixture = new Fixture(directory); var peer = mockStatic(RuntimeProxyTransport.class)) {
            peer.when(RuntimeProxyTransport::currentWorkloadPeer).thenReturn(Optional.of(fixture.peer));
            assertThat(fixture.terminal().getStatusCode().value()).isEqualTo(200);
            fixture.absent = true;
            fixture.namespaceDefect = "qualified-annotation";
            assertThat(fixture.complete().getStatusCode().value()).isEqualTo(200);
            verify(fixture.cleanup).complete(any(), anyString(), anySet(), any());
        }
    }

    @Test
    void aCopiedTerminalRequestAndApiAbsenceCannotCreateThePrivateProof() throws Exception {
        try (var fixture = new Fixture(directory); var peer = mockStatic(RuntimeProxyTransport.class)) {
            peer.when(RuntimeProxyTransport::currentWorkloadPeer).thenReturn(Optional.of(fixture.peer));
            fixture.absent = true;
            assertThat(fixture.complete().getStatusCode().value()).isEqualTo(403);
            assertThat(fixture.api.requests).hasValue(0);
            verifyNoInteractions(fixture.cleanup);
        }
    }

    @Test
    void aRunningPodCannotBePromotedToPhysicalTerminalOrCleanupDone() throws Exception {
        try (var fixture = new Fixture(directory); var peer = mockStatic(RuntimeProxyTransport.class)) {
            peer.when(RuntimeProxyTransport::currentWorkloadPeer).thenReturn(Optional.of(fixture.peer));
            fixture.running = true;
            assertThat(fixture.terminal().getStatusCode().is2xxSuccessful()).isFalse();
            fixture.absent = true;
            assertThat(fixture.complete().getStatusCode().value()).isEqualTo(403);
            verifyNoInteractions(fixture.cleanup);
        }
    }

    @Test
    void aRunnerWithoutTheApprovedNativeCutoffCannotReceiveALaunchBinding() throws Exception {
        for (int deadline : new int[]{26, 28, 30, 180}) {
            try (var fixture = new Fixture(directory); var peer = mockStatic(RuntimeProxyTransport.class)) {
                peer.when(RuntimeProxyTransport::currentWorkloadPeer).thenReturn(Optional.of(fixture.peer));
                for (String pointer : List.of("/podSpec", "/job/spec/template/spec")) {
                    ((ObjectNode) fixture.profile.at(pointer)).put("activeDeadlineSeconds", deadline);
                }
                Files.write(fixture.profileFile, Fixture.JSON.writeValueAsBytes(fixture.profile));
                fixture.currentRun.set(fixture.queued());
                var launch = fixture.service.reconcile(new ByteArrayInputStream(ControllerWire.launchRequest(LOCATOR)));
                assertThat(launch.getStatusCode().is2xxSuccessful()).isFalse();
                assertThat(fixture.api.requests).hasValue(0);
                verifyNoInteractions(fixture.cleanup);
                verify(fixture.kernel, never()).observe(any(), any());
            }
        }
    }

    @Test
    void automaticJobRetriesCannotReceiveALaunchBinding() throws Exception {
        try (var fixture = new Fixture(directory); var peer = mockStatic(RuntimeProxyTransport.class)) {
            peer.when(RuntimeProxyTransport::currentWorkloadPeer).thenReturn(Optional.of(fixture.peer));
            ((ObjectNode) fixture.profile.path("job").path("spec")).put("backoffLimit", 1);
            Files.write(fixture.profileFile, Fixture.JSON.writeValueAsBytes(fixture.profile));
            fixture.currentRun.set(fixture.queued());
            var launch = fixture.service.reconcile(new ByteArrayInputStream(ControllerWire.launchRequest(LOCATOR)));
            assertThat(launch.getStatusCode().is2xxSuccessful()).isFalse();
            assertThat(fixture.api.requests).hasValue(0);
            verifyNoInteractions(fixture.cleanup);
        }
    }

    @Test
    void actualGatedAndRunningObservationsReturnFreshPersistedRevisionsInsteadOfEchoingLaunch() throws Exception {
        try (var fixture = new Fixture(directory); var peer = mockStatic(RuntimeProxyTransport.class)) {
            peer.when(RuntimeProxyTransport::currentWorkloadPeer).thenReturn(Optional.of(fixture.peer));
            fixture.currentRun.set(fixture.queued());
            var launch = fixture.service.reconcile(new ByteArrayInputStream(ControllerWire.launchRequest(LOCATOR)));
            verifyNoInteractions(fixture.cleanup);
            verify(fixture.kernel, never()).observe(any(), any());
            assertThat(launch.getStatusCode().value()).isEqualTo(200);
            assertThat(ControllerWire.readLaunchReply(launch.getBody(), LOCATOR).runRevision()).isEqualTo(7);
            assertThat(fixture.api.requests).hasValue(0);
            fixture.gated = true;
            var request = new ControllerWire.ObservationRequest(LOCATOR, POD);
            when(fixture.kernel.observe(any(), any())).thenAnswer(call -> {
                AiRuntimeState.WorkloadObservation observation = call.getArgument(0);
                fixture.currentRun.set(fixture.observed(observation.registered()));
                return AiRuntimeState.Transition.empty(AiRuntimeState.Status.APPLIED);
            });
            var eligible = fixture.service
                    .reconcile(new ByteArrayInputStream(
                            ControllerWire.observationRequest(ControllerWire.Operation.ELIGIBLE, request)));
            assertThat(eligible.getStatusCode().value()).isEqualTo(200);
            var first = ControllerWire
                    .readObservationReply(eligible.getBody(), ControllerWire.Operation.ELIGIBLE, request);
            assertThat(first.runRevision()).isEqualTo(8);
            assertThat(first.fence()).isEqualTo(3);
            assertThat(first.observationSequence()).isEqualTo(1);
            fixture.gated = false;
            fixture.running = true;
            var registered = fixture.service
                    .register(new ByteArrayInputStream(
                            ControllerWire.observationRequest(ControllerWire.Operation.REGISTER, request)));
            assertThat(registered.getStatusCode().value()).isEqualTo(200);
            var second = ControllerWire
                    .readObservationReply(registered.getBody(), ControllerWire.Operation.REGISTER, request);
            assertThat(second.runRevision()).isEqualTo(11);
            assertThat(second.fence()).isEqualTo(3);
            assertThat(second.observationSequence()).isEqualTo(2);
            assertThat(second.jobUid()).isEqualTo(JOB);
            var observations = org.mockito.ArgumentCaptor.forClass(AiRuntimeState.WorkloadObservation.class);
            verify(fixture.kernel, times(2)).observe(observations.capture(), any());
            assertThat(observations.getAllValues().get(0).expected().runRevision()).isEqualTo(7);
            assertThat(observations.getAllValues().get(0).registered()).isFalse();
            assertThat(observations.getAllValues().get(1).expected().runRevision()).isEqualTo(8);
            assertThat(observations.getAllValues().get(1).registered()).isTrue();
            assertThat(observations.getAllValues().get(1).podUid()).isEqualTo(POD.toString());
            verifyNoInteractions(fixture.cleanup);
            assertThat(fixture.api.failure.get()).isNull();
        }
    }

    @Test
    void distinctOwnedPodsReachEligibilityAndRegistrationWithoutLosingEitherIdentity() throws Exception {
        try (var fixture = new Fixture(directory); var peer = mockStatic(RuntimeProxyTransport.class)) {
            peer.when(RuntimeProxyTransport::currentWorkloadPeer).thenReturn(Optional.of(fixture.peer));
            fixture.currentRun.set(fixture.queued());
            fixture.duplicatePods = true;
            fixture.gated = true;
            when(fixture.kernel.observe(any(), any())).thenAnswer(call -> {
                fixture.currentRun.set(fixture.observed(call.getArgument(0)));
                return AiRuntimeState.Transition.empty(AiRuntimeState.Status.APPLIED);
            });
            for (var operation : ControllerWire.Operation.values()) {
                for (UUID pod : List.of(POD, SECOND_POD)) {
                    var request = new ControllerWire.ObservationRequest(LOCATOR, pod);
                    var body = new ByteArrayInputStream(ControllerWire.observationRequest(operation, request));
                    var response = operation == ControllerWire.Operation.ELIGIBLE
                            ? fixture.service.reconcile(body)
                            : fixture.service.register(body);
                    assertThat(response.getStatusCode().value()).isEqualTo(200);
                    assertThat(ControllerWire
                            .readObservationReply(response.getBody(), operation, request)
                            .request()
                            .podUid()).isEqualTo(pod);
                }
                fixture.gated = false;
                fixture.running = true;
            }
            var current = fixture.currentRun.get();
            assertThat(current.workloads())
                    .extracting(row -> row.ref().podUid())
                    .containsExactlyInAnyOrder(POD.toString(), SECOND_POD.toString());
            assertThat(current.workloads()).allMatch(row -> row.state() == AiRuntimeState.WorkloadState.REGISTERED);
            assertThat(current.attempt().state()).isEqualTo(AiRuntimeState.AttemptState.LAUNCHING);
            assertThat(current.attempt().claim()).isEmpty();
            verify(fixture.kernel, times(4)).observe(any(), any());
            verifyNoInteractions(fixture.cleanup);
            assertThat(fixture.api.failure.get()).isNull();
        }
    }

    @Test
    void aSecondRegistrationPreservesTheAlreadyClaimedWinner() throws Exception {
        try (var fixture = new Fixture(directory); var peer = mockStatic(RuntimeProxyTransport.class)) {
            peer.when(RuntimeProxyTransport::currentWorkloadPeer).thenReturn(Optional.of(fixture.peer));
            fixture.currentRun.set(fixture.observed(true));
            var winner = fixture.currentRun.get().attempt().claim().orElseThrow();
            fixture.duplicatePods = true;
            fixture.running = true;
            when(fixture.kernel.observe(any(), any())).thenAnswer(call -> {
                fixture.currentRun.set(fixture.observed(call.getArgument(0)));
                return AiRuntimeState.Transition.empty(AiRuntimeState.Status.APPLIED);
            });
            var request = new ControllerWire.ObservationRequest(LOCATOR, SECOND_POD);
            var reply = fixture.service
                    .register(new ByteArrayInputStream(
                            ControllerWire.observationRequest(ControllerWire.Operation.REGISTER, request)));
            assertThat(reply.getStatusCode().value()).isEqualTo(200);
            assertThat(fixture.currentRun.get().workloads()).hasSize(2);
            assertThat(fixture.currentRun.get().attempt().claim()).contains(winner);
            assertThat(fixture.currentRun.get().attempt().state()).isEqualTo(AiRuntimeState.AttemptState.CLAIMED);
            verify(fixture.kernel, never()).bootstrap(any(), any(), any());
            verifyNoInteractions(fixture.cleanup);
        }
    }

    @ParameterizedTest
    @ValueSource(strings = {"uid", "name", "foreign-job", "spec"})
    void ambiguousOrForeignOwnedSiblingsCannotPublishAnObservation(String defect) throws Exception {
        try (var fixture = new Fixture(directory); var peer = mockStatic(RuntimeProxyTransport.class)) {
            peer.when(RuntimeProxyTransport::currentWorkloadPeer).thenReturn(Optional.of(fixture.peer));
            fixture.currentRun.set(fixture.queued());
            fixture.duplicatePods = true;
            fixture.secondDefect = defect;
            fixture.gated = true;
            var request = new ControllerWire.ObservationRequest(LOCATOR, POD);
            var response = fixture.service
                    .reconcile(new ByteArrayInputStream(
                            ControllerWire.observationRequest(ControllerWire.Operation.ELIGIBLE, request)));
            assertThat(response.getStatusCode().value()).isIn(403, 503);
            verify(fixture.kernel, never()).observe(any(), any());
            verifyNoInteractions(fixture.cleanup);
        }
    }

    @Test
    void terminalCleanupCoversEveryPersistedOwnedPodBeforeOneWriterCall() throws Exception {
        try (var fixture = new Fixture(directory); var peer = mockStatic(RuntimeProxyTransport.class)) {
            peer.when(RuntimeProxyTransport::currentWorkloadPeer).thenReturn(Optional.of(fixture.peer));
            fixture.duplicatePods = true;
            fixture.addSecondClosedPod();
            var expected = fixture.fullControl();
            assertThat(fixture.terminal(expected).getStatusCode().value()).isEqualTo(200);
            fixture.absent = true;
            assertThat(fixture.complete(expected).getStatusCode().value()).isEqualTo(200);
            var workloads = org.mockito.ArgumentCaptor.forClass(Set.class);
            verify(fixture.cleanup).complete(any(), anyString(), workloads.capture(), any());
            assertThat(workloads.getValue()).hasSize(2);
            assertThat(fixture.api.failure.get()).isNull();
        }
    }

    @Test
    void secondPodCannotResetTheSharedFiveSecondTerminalBudget() throws Exception {
        try (var fixture = new Fixture(directory); var peer = mockStatic(RuntimeProxyTransport.class)) {
            peer.when(RuntimeProxyTransport::currentWorkloadPeer).thenReturn(Optional.of(fixture.peer));
            fixture.duplicatePods = true;
            fixture.addSecondClosedPod();
            fixture.expireOnSecondPodRead = true;
            var expected = fixture.fullControl();
            assertThat(fixture.terminal(expected).getStatusCode().value()).isEqualTo(503);
            fixture.expireOnSecondPodRead = false;
            assertThat(fixture.complete(expected).getStatusCode().value()).isEqualTo(403);
            verifyNoInteractions(fixture.cleanup);
        }
    }

    @Test
    void unpersistedOwnedSiblingCannotBeHiddenFromTerminalProof() throws Exception {
        try (var fixture = new Fixture(directory); var peer = mockStatic(RuntimeProxyTransport.class)) {
            peer.when(RuntimeProxyTransport::currentWorkloadPeer).thenReturn(Optional.of(fixture.peer));
            fixture.duplicatePods = true;
            assertThat(fixture.terminal().getStatusCode().value()).isEqualTo(403);
            fixture.absent = true;
            assertThat(fixture.complete().getStatusCode().value()).isEqualTo(403);
            verifyNoInteractions(fixture.cleanup);
        }
    }

    @Test
    void persistedPodNameCannotBeReplacedWhileReusingItsUid() throws Exception {
        try (var fixture = new Fixture(directory); var peer = mockStatic(RuntimeProxyTransport.class)) {
            peer.when(RuntimeProxyTransport::currentWorkloadPeer).thenReturn(Optional.of(fixture.peer));
            fixture.currentRun.set(fixture.observed(false));
            fixture.running = true;
            fixture.renamedFirstPod = true;
            var body = ControllerWire
                    .observationRequest(ControllerWire.Operation.REGISTER,
                            new ControllerWire.ObservationRequest(LOCATOR, POD));
            assertThat(fixture.service.register(new ByteArrayInputStream(body)).getStatusCode().value()).isEqualTo(403);
            verify(fixture.kernel, never()).observe(any(), any());
        }
    }

    @Test
    void aCopiedForeignPodUidCannotBecomeAnObservedOrRegisteredWorkload() throws Exception {
        try (var fixture = new Fixture(directory); var peer = mockStatic(RuntimeProxyTransport.class)) {
            peer.when(RuntimeProxyTransport::currentWorkloadPeer).thenReturn(Optional.of(fixture.peer));
            fixture.currentRun.set(fixture.queued());
            fixture.gated = true;
            var request = new ControllerWire.ObservationRequest(LOCATOR, UUID.randomUUID());
            var response = fixture.service
                    .reconcile(new ByteArrayInputStream(
                            ControllerWire.observationRequest(ControllerWire.Operation.ELIGIBLE, request)));
            assertThat(response.getStatusCode().value()).isEqualTo(403);
            verify(fixture.kernel, never()).observe(any(), any());
            verifyNoInteractions(fixture.cleanup);
        }
    }

    @Test
    void controllerRevocationDuringActualApiObservationCannotReachTheWorkloadWriter() throws Exception {
        try (var fixture = new Fixture(directory); var peer = mockStatic(RuntimeProxyTransport.class)) {
            peer.when(RuntimeProxyTransport::currentWorkloadPeer).thenReturn(Optional.of(fixture.peer));
            fixture.currentRun.set(fixture.queued());
            fixture.gated = true;
            when(fixture.authority.requireCurrent(any(), any()))
                    .thenReturn(fixture.authorityEvidence())
                    .thenThrow(new org.springframework.security.access.AccessDeniedException("revoked"));
            var request = new ControllerWire.ObservationRequest(LOCATOR, POD);
            var response = fixture.service
                    .reconcile(new ByteArrayInputStream(
                            ControllerWire.observationRequest(ControllerWire.Operation.ELIGIBLE, request)));
            assertThat(fixture.api.requests.get()).isGreaterThan(0);
            assertThat(response.getStatusCode().value()).isEqualTo(403);
            verify(fixture.authority, times(2)).requireCurrent(org.mockito.ArgumentMatchers.eq(fixture.peer), any());
            verify(fixture.kernel, never()).observe(any(), any());
            verifyNoInteractions(fixture.cleanup);
            assertThat(fixture.api.failure.get()).isNull();
        }
    }

    @Test
    void controllerRevocationDuringActualAbsenceCannotReachTheCleanupWriter() throws Exception {
        try (var fixture = new Fixture(directory); var peer = mockStatic(RuntimeProxyTransport.class)) {
            peer.when(RuntimeProxyTransport::currentWorkloadPeer).thenReturn(Optional.of(fixture.peer));
            assertThat(fixture.terminal().getStatusCode().value()).isEqualTo(200);
            org.mockito.Mockito.clearInvocations(fixture.authority);
            int readsBeforeCleanup = fixture.api.requests.get();
            when(fixture.authority.requireCurrent(any(), any()))
                    .thenReturn(fixture.authorityEvidence())
                    .thenThrow(new org.springframework.security.access.AccessDeniedException("revoked"));
            fixture.absent = true;
            assertThat(fixture.complete().getStatusCode().value()).isEqualTo(403);
            assertThat(fixture.absenceNamespaceReads).hasValue(2);
            assertThat(fixture.api.requests.get()).isGreaterThan(readsBeforeCleanup);
            verify(fixture.authority, times(2)).requireCurrent(org.mockito.ArgumentMatchers.eq(fixture.peer), any());
            verifyNoInteractions(fixture.cleanup);
            assertThat(fixture.api.failure.get()).isNull();
        }
    }

    private static final class Fixture implements AutoCloseable {
        private static final com.fasterxml.jackson.databind.ObjectMapper JSON = ObjectMapperFactory.aiKubernetesWire();
        private final Instant now = Instant.now();
        private final AtomicLong nanos = new AtomicLong();
        private final java.util.concurrent.atomic.AtomicReference<AiRuntimeState.RunSnapshot> currentRun = new java.util.concurrent.atomic.AtomicReference<>();
        private final AtomicInteger absenceNamespaceReads = new AtomicInteger();
        private final AiRuntimeKernel kernel = mock(AiRuntimeKernel.class);
        private final AiRuntimeCleanupWriter cleanup = mock(AiRuntimeCleanupWriter.class);
        private final AiRuntimeControllerAuthority authority = mock(AiRuntimeControllerAuthority.class);
        private final ControllerServiceApiFixture api;
        private final AiRuntimeControllerServiceImpl service;
        private final ObjectNode profile;
        private final Path profileFile;
        private final RuntimePeer peer = new RuntimePeer(RuntimePeerRole.CONTROLLER,
                new RuntimeProxyCertificateClaims("lab", "runtime", "controller", "controller-one", UUID.randomUUID()));
        private volatile boolean absent;
        private volatile boolean running;
        private volatile boolean gated;
        private volatile boolean duplicatePods;
        private volatile boolean expireOnSecondPodRead;
        private volatile boolean renamedFirstPod;
        private volatile String secondDefect;
        private volatile int changedNamespaceRead;
        private volatile String namespaceDefect;

        private Fixture(Path directory) throws Exception {
            this(directory, true);
        }

        private Fixture(Path directory, boolean featureEnabled) throws Exception {
            api = new ControllerServiceApiFixture(directory);
            byte[] bytes;
            try (var input = AiRuntimeControllerServiceTest.class
                    .getResourceAsStream("/ai/controller-service-profile.json")) {
                bytes = java.util.Objects.requireNonNull(input).readAllBytes();
            }
            profile = (ObjectNode) JSON.readTree(bytes);
            Path file = Files.createTempFile(directory, "synthetic-controller-profile-", ".json");
            profileFile = file;
            Files.write(file, bytes);
            Files.setPosixFilePermissions(file, PosixFilePermissions.fromString("rw-------"));
            var source = new AiRuntimeControllerServiceImpl.Source(api.configuration(),
                    Map
                            .of(RuntimePeerRole.RUNNER_PROXY, file, RuntimePeerRole.GATEWAY_RUN, file,
                                    RuntimePeerRole.GATEWAY_MANAGEMENT, file));
            var beans = new StaticListableBeanFactory(Map.of("authority", authority, "source", source));
            service = new AiRuntimeControllerServiceImpl(kernel, cleanup,
                    beans.getBeanProvider(AiRuntimeControllerAuthority.class),
                    beans.getBeanProvider(AiRuntimeControllerServiceImpl.Source.class),
                    Clock.fixed(now, ZoneOffset.UTC), nanos::get, new AiFeatureGate(featureEnabled));
            currentRun.set(snapshot());
            when(kernel.snapshot(any(), any())).thenAnswer(call -> Optional.of(currentRun.get()));
            var controlPins = AiRuntimeState.ControlPins.forAttempt(currentRun.get().attempt().spec());
            var version = new AiRuntimeState.ControlVersion(2);
            var readiness = new AiRuntimeState.ReadinessObservation(version, controlPins, 1, UUID.randomUUID(), now,
                    now.plusSeconds(30));
            when(kernel.control(any()))
                    .thenReturn(Optional
                            .of(new AiRuntimeState.ControlSnapshot(version, true, Optional.of(controlPins),
                                    Optional.of(readiness), now, now)));
            when(cleanup.complete(any(), anyString(), anySet(), any()))
                    .thenReturn(AiRuntimeState.Transition.empty(AiRuntimeState.Status.APPLIED));
            api.responder = this::respond;
        }

        /** Concrete record returned by the mocked native authority boundary; not a deployed proof. */
        private com.otilm.ai.controller.KubernetesObserver.Evidence authorityEvidence() {
            return new com.otilm.ai.controller.KubernetesObserver.Evidence(
                    new com.otilm.ai.controller.KubernetesSnapshotVerifier.Observation(
                            peer.subject().podUid().toString(),
                            UUID.fromString("63e7a565-a4e3-46cf-8fb6-96651933835a").toString(), "controller-pod-rv",
                            "synthetic-controller-node",
                            com.otilm.ai.controller.KubernetesSnapshotVerifier.Stage.RUNNING),
                    new com.otilm.ai.controller.KubernetesObserver.Versions("controller-ns-rv", "controller-sa-rv",
                            "controller-job-rv", "controller-list-rv", "controller-runtime-rv"));
        }

        private org.springframework.http.ResponseEntity<byte[]> resume() {
            return service.status(new ByteArrayInputStream(ControllerWire.cleanupResumeRequest(LOCATOR)));
        }

        private void cleanupState(AiRuntimeState.CleanupState state) {
            var before = currentRun.get();
            var old = before.launch();
            var launch = new AiRuntimeState.LaunchSnapshot(old.spec(), old.jobName(), old.jobUid(),
                    old.observationSequence(), state, old.createdAt(), old.updatedAt());
            currentRun
                    .set(new AiRuntimeState.RunSnapshot(before.spec(), before.state(), before.revision(),
                            before.fence(), before.attemptsUsed(), before.attempt(), launch, before.workloads(),
                            before.controlGeneration(), now, now));
        }

        private void incompleteBinding(boolean jobMissing) {
            var before = currentRun.get();
            var old = before.launch();
            var launch = new AiRuntimeState.LaunchSnapshot(old.spec(), old.jobName(),
                    jobMissing ? Optional.empty() : old.jobUid(), old.observationSequence(), old.cleanup(),
                    old.createdAt(), old.updatedAt());
            currentRun
                    .set(new AiRuntimeState.RunSnapshot(before.spec(), before.state(), before.revision(),
                            before.fence(), before.attemptsUsed(), before.attempt(), launch,
                            jobMissing ? before.workloads() : List.of(), before.controlGeneration(), now, now));
        }

        private org.springframework.http.ResponseEntity<byte[]> terminal() {
            return terminal(EXPECTED);
        }

        private org.springframework.http.ResponseEntity<byte[]> terminal(ControllerWire.Control expected) {
            return service
                    .status(new ByteArrayInputStream(ControllerWire
                            .controlRequest(ControllerWire.ControlOperation.TERMINAL, LOCATOR, expected)));
        }

        private org.springframework.http.ResponseEntity<byte[]> complete() {
            return complete(EXPECTED);
        }

        private org.springframework.http.ResponseEntity<byte[]> complete(ControllerWire.Control expected) {
            return service
                    .cleanup(new ByteArrayInputStream(
                            ControllerWire.controlRequest(ControllerWire.ControlOperation.CLEANUP, LOCATOR, expected)));
        }

        private AiRuntimeState.RunSnapshot snapshot() {
            var pin = profile.path("pins");
            var launch = new AiRuntimeState.LaunchSpec("lab", "runtime", pin.path("namespaceUid").textValue(), "runner",
                    pin.path("serviceAccountUid").textValue(), pin.path("templateDigest").textValue(), "ilm-runsc");
            var attempt = new AiRuntimeState.AttemptSpec(ATTEMPT, now.plusSeconds(60), now.plusSeconds(90),
                    pin.path("imageDigest").textValue(), 11, 12, 13, "v1", launch);
            return new AiRuntimeState.RunSnapshot(
                    new AiRuntimeState.RunSpec(
                            RUN, Optional.empty(), UUID.randomUUID(), "synthetic", 2, 2, 5, now.plusSeconds(120)),
                    AiRuntimeState.RunState.CANCELLED, 10, 4, 1,
                    new AiRuntimeState.AttemptSnapshot(attempt, 1, AiRuntimeState.AttemptState.FENCED, 4,
                            Optional.of(AiRuntimeState.FailureReason.INVALIDATED), Optional.empty(), 2, now, now),
                    new AiRuntimeState.LaunchSnapshot(launch, JOB_NAME, Optional.of(JOB.toString()), 2,
                            AiRuntimeState.CleanupState.DUE, now, now),
                    List
                            .of(new AiRuntimeState.WorkloadSnapshot(
                                    new AiRuntimeState.WorkloadRef("lab", POD.toString()), POD_NAME, JOB.toString(),
                                    AiRuntimeState.WorkloadState.CLOSED, 2, now.plusSeconds(20), Optional.empty(),
                                    Optional.empty(), 0, Optional.empty(), now, now)),
                    2, now, now);
        }

        private void addSecondClosedPod() {
            var before = currentRun.get();
            var rows = new java.util.ArrayList<>(before.workloads());
            var first = rows.getFirst();
            rows
                    .add(new AiRuntimeState.WorkloadSnapshot(
                            new AiRuntimeState.WorkloadRef("lab", SECOND_POD.toString()), SECOND_POD_NAME,
                            first.jobUid(), first.state(), first.observationSequence(), first.observationValidUntil(),
                            first.firstPendingAt(), first.pendingDeadline(), first.pendingReturns(),
                            first.bootstrapConsumedAt(), first.createdAt(), first.updatedAt()));
            currentRun
                    .set(new AiRuntimeState.RunSnapshot(before.spec(), before.state(), before.revision(),
                            before.fence(), before.attemptsUsed(), before.attempt(), before.launch(), rows,
                            before.controlGeneration(), now, now));
        }

        private ControllerWire.Control fullControl() {
            var run = currentRun.get();
            return new ControllerWire.Control(LOCATOR, run.revision(), run.fence(), JOB, run
                    .workloads()
                    .stream()
                    .map(row -> new ControllerWire.Pod(row.ref().cluster(), UUID.fromString(row.ref().podUid())))
                    .collect(java.util.stream.Collectors.toSet()));
        }

        private AiRuntimeState.RunSnapshot queued() {
            var base = snapshot();
            var attempt = new AiRuntimeState.AttemptSnapshot(base.attempt().spec(), 1,
                    AiRuntimeState.AttemptState.LAUNCHING, 3, Optional.empty(), Optional.empty(), 2, now, now);
            var launch = new AiRuntimeState.LaunchSnapshot(base.launch().spec(), JOB_NAME, Optional.empty(), 0,
                    AiRuntimeState.CleanupState.NONE, now, now);
            return new AiRuntimeState.RunSnapshot(base.spec(), AiRuntimeState.RunState.QUEUED, 7, 3, 1, attempt, launch,
                    List.of(), 2, now, now);
        }

        private AiRuntimeState.RunSnapshot observed(boolean registered) {
            var base = queued();
            var ref = new AiRuntimeState.WorkloadRef("lab", POD.toString());
            Optional<AiRuntimeState.Claim> claim = registered
                    ? Optional
                            .of(new AiRuntimeState.Claim(
                                    new AiRuntimeState.ClaimBinding(RUN, ATTEMPT, ref, UUID.randomUUID(), 3),
                                    now.plusSeconds(5), 0))
                    : Optional.empty();
            var attempt = new AiRuntimeState.AttemptSnapshot(base.attempt().spec(), 1,
                    registered ? AiRuntimeState.AttemptState.CLAIMED : AiRuntimeState.AttemptState.LAUNCHING, 3,
                    Optional.empty(), claim, 2, now, now);
            var launch = new AiRuntimeState.LaunchSnapshot(base.launch().spec(), JOB_NAME, Optional.of(JOB.toString()),
                    registered ? 2 : 1, AiRuntimeState.CleanupState.NONE, now, now);
            var row = new AiRuntimeState.WorkloadSnapshot(ref, POD_NAME, JOB.toString(),
                    registered ? AiRuntimeState.WorkloadState.REGISTERED : AiRuntimeState.WorkloadState.ELIGIBLE,
                    registered ? 2 : 1, now.plusSeconds(20), Optional.empty(), Optional.empty(), 0,
                    registered ? Optional.of(now) : Optional.empty(), now, now);
            return new AiRuntimeState.RunSnapshot(base.spec(),
                    registered ? AiRuntimeState.RunState.RUNNING : AiRuntimeState.RunState.QUEUED, registered ? 11 : 8,
                    3, 1, attempt, launch, List.of(row), 2, now, now);
        }

        private AiRuntimeState.RunSnapshot observed(AiRuntimeState.WorkloadObservation observation) {
            var before = currentRun.get();
            var ref = new AiRuntimeState.WorkloadRef(observation.cluster(), observation.podUid());
            var rows = new java.util.ArrayList<>(before.workloads());
            rows.removeIf(row -> row.ref().equals(ref));
            rows
                    .add(new AiRuntimeState.WorkloadSnapshot(ref, observation.podName(), observation.jobUid(),
                            observation.registered()
                                    ? AiRuntimeState.WorkloadState.REGISTERED
                                    : AiRuntimeState.WorkloadState.ELIGIBLE,
                            observation.sequence(), observation.validUntil(), Optional.empty(), Optional.empty(), 0,
                            observation.registered() ? Optional.of(now) : Optional.empty(), now, now));
            var launch = new AiRuntimeState.LaunchSnapshot(before.launch().spec(), JOB_NAME,
                    Optional.of(JOB.toString()), observation.sequence(), AiRuntimeState.CleanupState.NONE, now, now);
            return new AiRuntimeState.RunSnapshot(before.spec(), before.state(), before.revision() + 1, before.fence(),
                    before.attemptsUsed(), before.attempt(), launch, List.copyOf(rows), before.controlGeneration(), now,
                    now);
        }

        private ControllerServiceApiFixture.Reply respond(String path) {
            try {
                ObjectNode value;
                if (path.equals("/api/v1/namespaces/runtime")) {
                    int read = absent ? absenceNamespaceReads.incrementAndGet() : 0;
                    value = object("v1", "Namespace", "runtime",
                            read == changedNamespaceRead && read != 0
                                    ? UUID.randomUUID().toString()
                                    : profile.path("pins").path("namespaceUid").textValue(),
                            false);
                    if (absent && "qualified-annotation".equals(namespaceDefect)) {
                        ((ObjectNode) value.path("metadata"))
                                .putObject("annotations")
                                .put("proof." + "a".repeat(200) + "/value", "synthetic");
                    }
                    String body = JSON.writeValueAsString(value);
                    if (absent && "duplicate".equals(namespaceDefect)) {
                        body = body.replace("\"kind\":\"Namespace\"", "\"kind\":\"Namespace\",\"kind\":\"Namespace\"");
                    } else if (absent && "trailing".equals(namespaceDefect)) {
                        body += " {}";
                    }
                    return new ControllerServiceApiFixture.Reply(200,
                            body
                                    .getBytes(absent && "utf16".equals(namespaceDefect)
                                            ? StandardCharsets.UTF_16
                                            : StandardCharsets.UTF_8));
                } else if (path.equals("/api/v1/namespaces/runtime/serviceaccounts/runner")) {
                    value = object("v1", "ServiceAccount", "runner",
                            profile.path("pins").path("serviceAccountUid").textValue(), true);
                } else if (path.equals("/apis/node.k8s.io/v1/runtimeclasses/ilm-runsc")) {
                    value = object("node.k8s.io/v1", "RuntimeClass", "ilm-runsc",
                            profile.path("runtime").path("uid").textValue(), false);
                    value.put("handler", "runsc");
                } else if (path.equals("/apis/batch/v1/namespaces/runtime/jobs/" + JOB_NAME)) {
                    if (absent) {
                        value = JSON
                                .createObjectNode()
                                .put("apiVersion", "v1")
                                .put("kind", "Status")
                                .put("reason", "NotFound")
                                .put("code", 404);
                        value.putObject("details").put("name", JOB_NAME).put("kind", "jobs").put("group", "batch");
                        return new ControllerServiceApiFixture.Reply(404, JSON.writeValueAsBytes(value));
                    }
                    value = ((ObjectNode) profile.path("job")).deepCopy();
                    ((ObjectNode) value.path("metadata")).put("uid", JOB.toString()).put("resourceVersion", "job-rv");
                    if (!running && !gated) {
                        value
                                .putObject("status")
                                .putArray("conditions")
                                .addObject()
                                .put("type", "Complete")
                                .put("status", "True");
                    }
                } else if (path.equals("/api/v1/namespaces/runtime/pods")) {
                    value = JSON.createObjectNode().put("apiVersion", "v1").put("kind", "PodList");
                    value.putObject("metadata").put("resourceVersion", "list-rv");
                    var items = value.putArray("items");
                    if (!absent) {
                        items.add(pod());
                        if (duplicatePods) {
                            items.add(pod(SECOND_POD_NAME, SECOND_POD));
                        }
                    }
                } else if (path.equals("/api/v1/namespaces/runtime/pods/" + POD_NAME)) {
                    value = pod();
                } else if (duplicatePods && path.equals("/api/v1/namespaces/runtime/pods/" + SECOND_POD_NAME)) {
                    value = pod(SECOND_POD_NAME, SECOND_POD);
                    if (expireOnSecondPodRead) {
                        nanos.set(5_000_000_000L);
                    }
                } else {
                    throw new AssertionError("Unexpected synthetic controller API path");
                }
                return new ControllerServiceApiFixture.Reply(200, JSON.writeValueAsBytes(value));
            } catch (Exception invalid) {
                throw new AssertionError(invalid);
            }
        }

        private ObjectNode pod() {
            return pod(POD_NAME, POD);
        }

        private ObjectNode pod(String podName, UUID podUid) {
            String identity = "containerd://" + (SECOND_POD.equals(podUid) ? "e" : "d").repeat(64);
            if (renamedFirstPod && podUid.equals(POD)) {
                podName = JOB_NAME + "-replacement";
            }
            var pod = object("v1", "Pod", podName, podUid.toString(), true);
            ((ObjectNode) pod.path("metadata")).set("labels", profile.path("podMetadata").path("labels"));
            ((ObjectNode) pod.path("metadata"))
                    .putArray("ownerReferences")
                    .addObject()
                    .put("apiVersion", "batch/v1")
                    .put("kind", "Job")
                    .put("name", JOB_NAME)
                    .put("uid", JOB.toString())
                    .put("controller", true);
            var spec = ((ObjectNode) profile.path("podSpec")).deepCopy();
            if (!gated) {
                spec.remove("schedulingGates");
                spec.put("nodeName", "synthetic-node");
            }
            pod.set("spec", spec);
            if (podUid.equals(SECOND_POD) && secondDefect != null) {
                var metadata = (ObjectNode) pod.path("metadata");
                switch (secondDefect) {
                    case "uid" -> metadata.put("uid", POD.toString());
                    case "name" -> metadata.put("name", POD_NAME);
                    case "foreign-job" -> ((ObjectNode) metadata.path("ownerReferences").get(0))
                            .put("uid", "e515611f-e4e3-47e4-8c2e-e53f415d0b89");
                    case "spec" -> ((ObjectNode) pod.path("spec")).put("hostPID", true);
                    default -> throw new IllegalArgumentException("Unknown synthetic defect");
                }
            }
            var status = pod.putObject("status").put("phase", gated ? "Pending" : running ? "Running" : "Succeeded");
            if (gated) {
                return pod;
            }
            var row = status
                    .putArray("containerStatuses")
                    .addObject()
                    .put("name", "runner")
                    .put("restartCount", 0)
                    .put("imageID", "containerd://sha256:" + "c".repeat(64))
                    .put("containerID", identity)
                    .put("ready", running)
                    .put("started", true);
            if (running) {
                row.putObject("state").putObject("running");
            } else {
                row
                        .putObject("state")
                        .putObject("terminated")
                        .put("exitCode", 0)
                        .put("containerID", identity)
                        .put("finishedAt", now.minusSeconds(1).toString());
            }
            return pod;
        }

        private static ObjectNode object(String version, String kind, String name, String uid, boolean namespaced) {
            var object = JSON.createObjectNode().put("apiVersion", version).put("kind", kind);
            var metadata = object.putObject("metadata").put("name", name).put("uid", uid).put("resourceVersion", "rv");
            if (namespaced) {
                metadata.put("namespace", "runtime");
            }
            return object;
        }

        @Override
        public void close() throws Exception {
            api.close();
        }
    }
}
