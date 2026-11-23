package com.otilm.core.integration.service;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.otilm.ai.runtime.protocol.ProtocolCodec;
import com.otilm.ai.runtime.protocol.RunBinding;
import com.otilm.ai.runtime.protocol.RunDispatchEnvelope;
import com.otilm.core.dao.repository.ai.AiModelRunOutcomeRepository;
import com.otilm.core.dao.repository.ai.AiRuntimeRepository;
import com.otilm.core.model.ai.AiModelDispatchState.ConnectionVersion;
import com.otilm.core.model.ai.AiModelDispatchState.RunPreparation;
import com.otilm.core.model.ai.AiModelDispatchState.RunRedemption;
import com.otilm.core.model.ai.AiRuntimeGatewayState.Deployment;
import com.otilm.core.model.ai.AiRuntimeGatewayState.Observation;
import com.otilm.core.model.ai.AiRuntimeState.Claim;
import com.otilm.core.model.ai.AiRuntimeState.ControlPins;
import com.otilm.core.model.ai.AiRuntimeState.ReadinessObservation;
import com.otilm.core.model.ai.AiRuntimeState.RunSnapshot;
import com.otilm.core.model.ai.AiRuntimeState.Status;
import com.otilm.core.security.ai.RuntimePeer;
import com.otilm.core.security.ai.RuntimePeerRole;
import com.otilm.core.security.ai.RuntimeProxyCertificateClaims;
import com.otilm.core.service.ai.AiRuntimeGatewayWire;
import com.otilm.core.service.ai.AiRuntimeGatewayWire.OutcomeRequest;
import com.otilm.core.service.ai.AiRuntimeKernel;
import com.otilm.core.service.ai.AiRuntimeOperationBudget;
import com.otilm.core.service.writer.ai.AiModelDispatchWriter;
import com.otilm.core.service.writer.ai.AiModelRunOutcomeWriter;
import com.otilm.core.service.writer.ai.AiRuntimeGatewayRegistrationWriter;
import com.otilm.core.util.AiModelDispatchFixture;
import com.otilm.core.util.AiRuntimeFixture;
import com.otilm.core.util.ai.BaseAiSpringBootTest;
import jakarta.persistence.EntityManager;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.sql.SQLException;
import java.time.Duration;
import java.time.Instant;
import java.util.Base64;
import java.util.HexFormat;
import java.util.UUID;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import javax.sql.DataSource;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.junit.jupiter.params.provider.ValueSource;
import org.springframework.aop.framework.ProxyFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.annotation.AnnotationTransactionAttributeSource;
import org.springframework.transaction.interceptor.TransactionInterceptor;

import static com.otilm.core.util.AiRuntimeFixture.expected;
import static com.otilm.core.util.AiRuntimeFixture.observation;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/** Real local persistence/registry fixtures; no native TLS/Kubernetes/Auth approval is inferred. */
class AiModelRunOutcomeITest extends BaseAiSpringBootTest {
    @Autowired
    private DataSource source;
    @Autowired
    private AiRuntimeKernel kernel;
    @Autowired
    private AiModelDispatchWriter dispatches;
    @Autowired
    private AiRuntimeGatewayRegistrationWriter registrations;
    @Autowired
    private AiModelRunOutcomeWriter writer;
    @Autowired
    private AiRuntimeRepository runtimeRepository;
    @Autowired
    private AiModelRunOutcomeRepository outcomeRepository;
    @Autowired
    private EntityManager entityManager;
    @Autowired
    private PlatformTransactionManager transactions;
    private RuntimePeer first;
    private RuntimePeer second;
    private RunSnapshot run;
    private Claim claim;
    private ConnectionVersion model;
    private RunPreparation preparation;
    private Deployment deployment;

    @BeforeEach
    void storedCurrentPeerAndPreparedIntent() throws Exception {
        AiModelDispatchFixture.drop(source);
        AiRuntimeFixture.install(source);
        Instant now = AiRuntimeFixture.now(source);
        var attempt = AiRuntimeFixture.attempt(now);
        var pins = ControlPins.forAttempt(attempt);
        var control = kernel
                .changeControl(kernel.control().orElseThrow().version(), pins)
                .value()
                .orElseThrow()
                .version();
        deployment = new Deployment(RuntimePeerRole.GATEWAY_RUN, control.generation(), AiRuntimeFixture.IMAGE,
                new com.otilm.core.model.ai.AiRuntimeState.LaunchSpec("cluster-one", "gateways", "gateway-namespace",
                        "gateway", "gateway-account", AiRuntimeFixture.TEMPLATE, "sandbox"));
        first = new RuntimePeer(RuntimePeerRole.GATEWAY_RUN, new RuntimeProxyCertificateClaims("cluster-one",
                "gateways", "gateway", "gateway-one", UUID.randomUUID()));
        second = new RuntimePeer(RuntimePeerRole.GATEWAY_RUN, new RuntimeProxyCertificateClaims("cluster-one",
                "gateways", "gateway", "gateway-two", UUID.randomUUID()));
        assertThat(registrations.configure(deployment, budget())).isTrue();
        for (RuntimePeer peer : new RuntimePeer[]{first, second}) {
            assertThat(registrations
                    .observe(
                            new Observation(deployment, peer.subject(), 1, UUID.randomUUID(), now, now.plusSeconds(25)),
                            budget()))
                    .isTrue();
        }
        assertThat(kernel
                .observeControl(new ReadinessObservation(control, pins, 1, UUID.randomUUID(), now, now.plusSeconds(30)))
                .status()).isEqualTo(Status.APPLIED);
        assertThat(kernel.enableControl(control).status()).isEqualTo(Status.APPLIED);
        run = kernel.create(control, AiRuntimeFixture.run(now), attempt);
        var pod = new com.otilm.core.model.ai.AiRuntimeState.WorkloadRef("cluster-one", UUID.randomUUID().toString());
        assertThat(kernel.observe(observation(current(), pod, 1, true)).status()).isEqualTo(Status.APPLIED);
        claim = kernel.bootstrap(expected(current()), pod).value().orElseThrow();
        model = AiModelDispatchFixture.approvedModel(source);
        AiModelDispatchFixture.runBudget(source, run.spec().runId(), model, 3, 128);
        preparation = new RunPreparation(UUID.randomUUID(), UUID.randomUUID(), expected(current()), claim.binding(),
                model, AiModelDispatchFixture.payload(32, "fixture"), 32, AiRuntimeFixture.now(source).plusSeconds(20));
        assertThat(dispatches.prepareRun(preparation, budget()).status()).isEqualTo(Status.APPLIED);
    }

    @Test
    void firstAssignmentIsImmutableAndExactReplay() {
        assertThat(writer.assign(preparation.intentId(), first, budget()).status()).isEqualTo(Status.APPLIED);
        assertThat(writer.assign(preparation.intentId(), first, budget()).status()).isEqualTo(Status.REPLAY);
        assertThat(writer.assign(preparation.intentId(), second, budget()).status()).isEqualTo(Status.CONFLICT);
        writer.requireAssigned(preparation.intentId(), first, budget());
        UUID intent = preparation.intentId();
        var rejectedBudget = budget();
        assertThatThrownBy(() -> writer.requireAssigned(intent, second, rejectedBudget))
                .isInstanceOf(AccessDeniedException.class);
    }

    @Test
    void unassignedReferenceHasNoDelegation() {
        UUID unknown = UUID.randomUUID();
        var rejectedBudget = budget();
        assertThatThrownBy(() -> writer.requireAssigned(unknown, first, rejectedBudget))
                .isInstanceOf(AccessDeniedException.class);
    }

    @Test
    void existingPreparedIntentHasNoDelegationBeforeFirstAssignment() {
        UUID intent = preparation.intentId();
        assertThat(registrations.current(first, budget())).isPresent();
        assertThat(registrations.current(second, budget())).isPresent();
        for (RuntimePeer peer : new RuntimePeer[]{first, second}) {
            var selectedBudget = budget();
            assertThatThrownBy(() -> writer.requireAssigned(intent, peer, selectedBudget))
                    .isInstanceOf(AccessDeniedException.class);
        }
    }

    private RunSnapshot current() {
        return kernel.snapshot(run.spec().runId()).orElseThrow();
    }

    private static AiRuntimeOperationBudget budget() {
        return AiRuntimeOperationBudget.start();
    }

    @Test
    void copiedPreparedReferenceCannotDelegateToAnotherCurrentRegisteredGateway() throws Exception {
        assertThat(registrations.current(second, budget())).isPresent();
        assertThat(writer.assign(preparation.intentId(), first, budget()).status()).isEqualTo(Status.APPLIED);
        String before = AiModelDispatchFixture.fingerprint(source);
        var selectedBudget = budget();
        UUID intent = preparation.intentId();
        assertThatThrownBy(() -> writer.requireAssigned(intent, second, selectedBudget))
                .isInstanceOf(AccessDeniedException.class);
        assertThat(writer.assign(intent, second, budget()).status()).isEqualTo(Status.CONFLICT);
        assertThat(AiModelDispatchFixture.fingerprint(source)).isEqualTo(before);
        assertThat(count("ai_model_run_gateway_assignment")).isEqualTo(1);
    }

    @Test
    void preparedUnassignedMissingAndWrongRoleReportsCannotAppend() throws Exception {
        var request = report(response("lab", true), UUID.randomUUID());
        assertThat(writer.append(request, first, budget()).status()).isEqualTo(Status.DENIED);
        assertThat(writer.assign(UUID.randomUUID(), first, budget()).status()).isEqualTo(Status.DENIED);
        var runner = new RuntimePeer(RuntimePeerRole.RUNNER_PROXY, first.subject());
        assertThat(writer.assign(preparation.intentId(), runner, budget()).status()).isEqualTo(Status.DENIED);
        assertThat(writer.append(request, runner, budget()).status()).isEqualTo(Status.DENIED);
        assertThat(writer.assign(preparation.intentId(), first, budget()).status()).isEqualTo(Status.APPLIED);
        assertThat(writer.append(request, first, budget()).status()).isEqualTo(Status.DENIED);
        assertThat(count("ai_model_run_outcome")).isZero();
    }

    @Test
    void preparedSchemaCannotCarryConsumedCorrelation() throws Exception {
        UUID correlation = UUID.randomUUID();
        try (var connection = source.getConnection();
                var statement = connection
                        .prepareStatement("UPDATE ai_model_run_intent SET gateway_correlation=? WHERE uuid=?")) {
            statement.setObject(1, correlation);
            statement.setObject(2, preparation.intentId());
            Throwable failure = org.assertj.core.api.Assertions.catchThrowable(statement::executeUpdate);
            assertThat(sqlState(failure)).isEqualTo("23514");
        }
    }

    @Test
    void assignmentCannotBeCreatedAfterAnUnassignedIntentWasConsumed() {
        assertThat(consumeFixture()).isNotNull();
        assertThat(writer.assign(preparation.intentId(), first, budget()).status()).isEqualTo(Status.DENIED);
    }

    @ParameterizedTest
    @CsvSource({
            "known,TEXT,true",
            "missing,TEXT,false",
            "invalid,INVALID,false",
            "over-limit,INVALID,false",
            "usage-mismatch,INVALID,false",
            "unknown,INVALID,false"})
    void storesOnlyServerDerivedResultAndNeverRefundsAllowance(String kind, String code, boolean knownUsage)
            throws Exception {
        UUID correlation = assignedAndConsumed();
        byte[] response = switch (kind) {
            case "known" -> response("lab", true);
            case "missing" -> response("lab", false);
            case "invalid" -> response("foreign-model", true);
            case "over-limit" -> new String(response("lab", true), StandardCharsets.UTF_8)
                    .replace("\"completion_tokens\":2", "\"completion_tokens\":33")
                    .replace("\"total_tokens\":3", "\"total_tokens\":34")
                    .getBytes(StandardCharsets.UTF_8);
            case "usage-mismatch" -> new String(response("lab", true), StandardCharsets.UTF_8)
                    .replace("\"total_tokens\":3", "\"total_tokens\":4")
                    .getBytes(StandardCharsets.UTF_8);
            default -> null;
        };
        var request = report(response, correlation);
        String before = AiModelDispatchFixture.fingerprint(source);
        RunSnapshot beforeRun = current();
        var outcome = writer.append(request, first, budget());
        assertThat(outcome.status()).isEqualTo(Status.APPLIED);
        var receipt = outcome.value().orElseThrow();
        assertThat(receipt.intentId()).isEqualTo(preparation.intentId());
        assertThat(receipt.gatewayCorrelation()).isEqualTo(correlation);
        assertThat(receipt.outcomeSha256()).isEqualTo(request.outcomeSha256());
        assertThat(receipt.resultVersion()).isPositive();
        try (var connection = source.getConnection();
                var statement = connection.createStatement();
                var rows = statement
                        .executeQuery(
                                "SELECT result_code,result_text,finish,prompt_tokens,completion_tokens,total_tokens,request_bytes,response_bytes FROM ai_model_run_outcome")) {
            assertThat(rows.next()).isTrue();
            assertThat(rows.getString(1)).isEqualTo(code);
            if (code.equals("TEXT")) {
                assertThat(rows.getString(2)).isEqualTo("assistant-result");
                assertThat(rows.getString(3)).isEqualTo("STOP");
            } else {
                assertThat(rows.getString(2)).isNull();
                assertThat(rows.getString(3)).isNull();
            }
            if (knownUsage) {
                assertThat(rows.getLong(4)).isEqualTo(1);
                assertThat(rows.getLong(5)).isEqualTo(2);
                assertThat(rows.getLong(6)).isEqualTo(3);
            } else {
                assertThat(rows.getObject(4)).isNull();
                assertThat(rows.getObject(5)).isNull();
                assertThat(rows.getObject(6)).isNull();
            }
            assertThat(rows.getBytes(7)).containsExactly(request.requestBytes());
            assertThat(rows.getBytes(8)).isEqualTo(response);
            assertThat(rows.next()).isFalse();
        }
        assertThat(AiModelDispatchFixture.fingerprint(source)).isEqualTo(before);
        assertThat(current()).isEqualTo(beforeRun);
        assertThat(AiModelDispatchFixture.reservedCalls(source, run.spec().runId())).isEqualTo(1);
        assertThat(AiModelDispatchFixture.reservedTokens(source, run.spec().runId(), false)).isEqualTo(32);
    }

    @Test
    void immutableExactReplayKeepsVersionAndConflictingReportCannotOverwrite() throws Exception {
        UUID correlation = assignedAndConsumed();
        var request = report(response("lab", true), correlation);
        var original = writer.append(request, first, budget()).value().orElseThrow();
        String before = outcomeFingerprint();
        var replay = writer.append(request, first, budget());
        assertThat(replay.status()).isEqualTo(Status.REPLAY);
        assertThat(replay.value()).contains(original);
        byte[] alternative = new String(request.requestBytes(), StandardCharsets.UTF_8)
                .concat(" ")
                .getBytes(StandardCharsets.UTF_8);
        var changed = new AiRuntimeGatewayWire().readOutcome(alternative);
        assertThat(writer.append(changed, first, budget()).status()).isEqualTo(Status.CONFLICT);
        assertThat(outcomeFingerprint()).isEqualTo(before);
    }

    @Test
    void ownedOriginalBytesOverrideManuallyConstructedRecordFields() throws Exception {
        UUID correlation = assignedAndConsumed();
        var original = report(response("lab", true), correlation);
        var supplied = new OutcomeRequest(999, "fabricated", UUID.randomUUID(), UUID.randomUUID(), null, "0".repeat(64),
                AiRuntimeGatewayWire.TransportCode.UNKNOWN, null, null, 0, null, "0".repeat(64),
                original.requestBytes(), "fabricated-provider-bytes".getBytes(StandardCharsets.UTF_8));
        var outcome = writer.append(supplied, first, budget());
        assertThat(outcome.status()).isEqualTo(Status.APPLIED);
        assertThat(outcome.value().orElseThrow().intentId()).isEqualTo(original.intentId());
        assertThat(outcome.value().orElseThrow().gatewayCorrelation()).isEqualTo(correlation);
        assertThat(outcome.value().orElseThrow().outcomeSha256()).isEqualTo(original.outcomeSha256());
        try (var connection = source.getConnection();
                var statement = connection.createStatement();
                var rows = statement
                        .executeQuery("SELECT request_bytes,response_bytes,result_text FROM ai_model_run_outcome")) {
            assertThat(rows.next()).isTrue();
            assertThat(rows.getBytes(1)).containsExactly(original.requestBytes());
            assertThat(rows.getBytes(2)).containsExactly(original.responseBytes());
            assertThat(rows.getString(3)).isEqualTo("assistant-result");
        }
    }

    @Test
    void malformedOwnedBodyCannotBorrowPlausibleParsedFields() throws Exception {
        UUID correlation = assignedAndConsumed();
        var original = report(response("lab", true), correlation);
        var supplied = new OutcomeRequest(original.protocolVersion(), original.kind(), original.intentId(),
                original.gatewayCorrelation(), original.binding(), original.payloadSha256(), original.transportCode(),
                original.responseBase64(), original.responseSha256(), original.responseByteCount(), original.usage(),
                original.outcomeSha256(), "{not-json".getBytes(StandardCharsets.UTF_8), original.responseBytes());
        var selectedBudget = budget();
        String before = AiModelDispatchFixture.fingerprint(source);
        assertThatThrownBy(() -> writer.append(supplied, first, selectedBudget))
                .isInstanceOf(IllegalArgumentException.class);
        assertThat(count("ai_model_run_outcome")).isZero();
        assertThat(AiModelDispatchFixture.fingerprint(source)).isEqualTo(before);
    }

    @Test
    void originalWhitespaceAndIndependentDigestArePersistedWithoutNormalization() throws Exception {
        UUID correlation = assignedAndConsumed();
        byte[] json = new ObjectMapper().writeValueAsBytes(outcomeNode(response("lab", true), correlation));
        byte[] original = (" \n" + new String(json, StandardCharsets.UTF_8) + " \t").getBytes(StandardCharsets.UTF_8);
        String independentlyHashed = HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(original));
        var request = new AiRuntimeGatewayWire().readOutcome(original);
        var outcome = writer.append(request, first, budget());
        assertThat(outcome.status()).isEqualTo(Status.APPLIED);
        assertThat(outcome.value().orElseThrow().outcomeSha256()).isEqualTo(independentlyHashed);
        try (var connection = source.getConnection();
                var statement = connection.createStatement();
                var rows = statement.executeQuery("SELECT request_bytes,outcome_sha256 FROM ai_model_run_outcome")) {
            assertThat(rows.next()).isTrue();
            assertThat(rows.getBytes(1)).containsExactly(original);
            assertThat(rows.getString(2)).isEqualTo(independentlyHashed);
        }
    }

    @Test
    void fullResponseAndDocumentLimitsFitStorageAndOneExtraByteIsRejected() throws Exception {
        UUID correlation = assignedAndConsumed();
        byte[] jsonResponse = response("lab", true);
        byte[] fullResponse = java.util.Arrays.copyOf(jsonResponse, 1_048_576);
        java.util.Arrays.fill(fullResponse, jsonResponse.length, fullResponse.length, (byte) ' ');
        byte[] json = new ObjectMapper().writeValueAsBytes(outcomeNode(fullResponse, correlation));
        assertThat(json.length).isLessThan(1_500_000);
        byte[] original = java.util.Arrays.copyOf(json, 1_500_000);
        java.util.Arrays.fill(original, json.length, original.length, (byte) ' ');
        String independentlyHashed = HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(original));
        var request = new AiRuntimeGatewayWire().readOutcome(original);
        String before = AiModelDispatchFixture.fingerprint(source);
        var outcome = writer.append(request, first, budget());
        assertThat(outcome.status()).isEqualTo(Status.APPLIED);
        assertThat(outcome.value().orElseThrow().outcomeSha256()).isEqualTo(independentlyHashed);
        try (var connection = source.getConnection();
                var statement = connection.createStatement();
                var rows = statement
                        .executeQuery(
                                "SELECT octet_length(request_bytes),octet_length(response_bytes),result_code FROM ai_model_run_outcome")) {
            assertThat(rows.next()).isTrue();
            assertThat(rows.getInt(1)).isEqualTo(1_500_000);
            assertThat(rows.getInt(2)).isEqualTo(1_048_576);
            assertThat(rows.getString(3)).isEqualTo("TEXT");
        }
        byte[] tooLarge = java.util.Arrays.copyOf(original, 1_500_001);
        tooLarge[tooLarge.length - 1] = ' ';
        var supplied = new OutcomeRequest(request.protocolVersion(), request.kind(), request.intentId(),
                request.gatewayCorrelation(), request.binding(), request.payloadSha256(), request.transportCode(),
                request.responseBase64(), request.responseSha256(), request.responseByteCount(), request.usage(),
                request.outcomeSha256(), tooLarge, request.responseBytes());
        var selectedBudget = budget();
        assertThatThrownBy(() -> writer.append(supplied, first, selectedBudget))
                .isInstanceOf(IllegalArgumentException.class);
        assertThat(count("ai_model_run_outcome")).isEqualTo(1);
        assertThat(AiModelDispatchFixture.fingerprint(source)).isEqualTo(before);
    }

    @Test
    void currentlyRegisteredForeignGatewayCannotReportForTheAssignedConsumedSender() throws Exception {
        UUID correlation = assignedAndConsumed();
        assertThat(registrations.current(second, budget())).isPresent();
        assertThat(writer.append(report(response("lab", true), correlation), second, budget()).status())
                .isEqualTo(Status.DENIED);
        assertThat(count("ai_model_run_outcome")).isZero();
        assertThat(writer.append(report(response("lab", true), correlation), first, budget()).status())
                .isEqualTo(Status.APPLIED);
    }

    @ParameterizedTest
    @ValueSource(strings = {
            "intent",
            "correlation",
            "run",
            "attempt",
            "runnerPod",
            "claim",
            "fence",
            "expiry",
            "digest",
            "nanoExpiry"})
    void everyConsumedBindingFieldMustMatchExactly(String field) throws Exception {
        UUID correlation = assignedAndConsumed();
        ObjectNode node = outcomeNode(response("lab", true), correlation);
        ObjectNode binding = (ObjectNode) node.get("binding");
        switch (field) {
            case "intent" -> node.put("intentId", UUID.randomUUID().toString());
            case "correlation" -> node.put("gatewayCorrelation", UUID.randomUUID().toString());
            case "run" -> binding.put("runId", UUID.randomUUID().toString());
            case "attempt" -> binding.put("attemptId", UUID.randomUUID().toString());
            case "runnerPod" -> binding.put("podUid", UUID.randomUUID().toString());
            case "claim" -> binding.put("claimId", UUID.randomUUID().toString());
            case "fence" -> binding.put("fence", claim.binding().fence() + 1);
            case "expiry" -> binding.put("expiresAt", preparation.expiresAt().plusSeconds(1).toString());
            case "nanoExpiry" -> binding.put("expiresAt", preparation.expiresAt().plusNanos(1).toString());
            default -> node.put("payloadSha256", "0".repeat(64));
        }
        var request = new AiRuntimeGatewayWire().readOutcome(new ObjectMapper().writeValueAsBytes(node));
        String before = AiModelDispatchFixture.fingerprint(source);
        assertThat(writer.append(request, first, budget()).status()).isEqualTo(Status.DENIED);
        assertThat(count("ai_model_run_outcome")).isZero();
        assertThat(AiModelDispatchFixture.fingerprint(source)).isEqualTo(before);
    }

    @Test
    void actualCancelledFencedAndExpiredBindingCanAppendEvidenceWithoutWorkRevival() throws Exception {
        Instant expiry = AiRuntimeFixture.now(source).plusSeconds(1);
        preparation = new RunPreparation(UUID.randomUUID(), UUID.randomUUID(), expected(current()), claim.binding(),
                model, preparation.payload(), 32, expiry);
        assertThat(dispatches.prepareRun(preparation, budget()).status()).isEqualTo(Status.APPLIED);
        UUID correlation = assignedAndConsumed();
        assertThat(kernel.cancel(run.spec().runId()).status()).isEqualTo(Status.APPLIED);
        org.awaitility.Awaitility
                .await("Original consumed binding expired by actual database clock")
                .pollInSameThread()
                .pollDelay(Duration.ZERO)
                .pollInterval(Duration.ofMillis(5))
                .atMost(Duration.ofSeconds(3))
                .until(() -> !AiRuntimeFixture.now(source).isBefore(expiry));
        var request = report(response("lab", true), correlation);
        String before = AiModelDispatchFixture.fingerprint(source);
        RunSnapshot cancelled = current();
        assertThat(cancelled.fence()).isGreaterThan(claim.binding().fence());
        assertThat(cancelled.attempt().state()).isEqualTo(com.otilm.core.model.ai.AiRuntimeState.AttemptState.FENCED);
        assertThat(writer.append(request, first, budget()).status()).isEqualTo(Status.APPLIED);
        assertThat(current()).isEqualTo(cancelled);
        assertThat(current().state()).isEqualTo(com.otilm.core.model.ai.AiRuntimeState.RunState.CANCELLED);
        assertThat(AiModelDispatchFixture.fingerprint(source)).isEqualTo(before);
    }

    @Test
    void revocationPreventsDelegationReplayAndLateAppend() throws Exception {
        UUID correlation = assignedAndConsumed();
        assertThat(registrations.revoke(first, budget())).isTrue();
        assertThat(registrations.current(first, budget())).isEmpty();
        assertThat(writer.assign(preparation.intentId(), first, budget()).status()).isEqualTo(Status.DENIED);
        var selectedBudget = budget();
        UUID intent = preparation.intentId();
        assertThatThrownBy(() -> writer.requireAssigned(intent, first, selectedBudget))
                .isInstanceOf(AccessDeniedException.class);
        assertThat(writer.append(report(response("lab", true), correlation), first, budget()).status())
                .isEqualTo(Status.DENIED);
    }

    @ParameterizedTest
    @ValueSource(strings = {"expired", "disabled", "generation"})
    void priorAssignmentCannotSurviveLossOfCurrentAuthority(String change) throws Exception {
        assertThat(writer.assign(preparation.intentId(), first, budget()).status()).isEqualTo(Status.APPLIED);
        if (change.equals("expired")) {
            Instant expiry = shortenRegistration();
            org.awaitility.Awaitility
                    .await("Actual previously assigned registration expired")
                    .pollInSameThread()
                    .pollDelay(Duration.ZERO)
                    .pollInterval(Duration.ofMillis(5))
                    .atMost(Duration.ofSeconds(2))
                    .until(() -> !AiRuntimeFixture.now(source).isBefore(expiry));
        } else if (change.equals("disabled")) {
            assertThat(kernel.disableControl(kernel.control().orElseThrow().version()).status())
                    .isEqualTo(Status.APPLIED);
        } else {
            advanceAndEnableControl();
            assertThat(registrations.current(first, budget())).isPresent();
            assertThat(kernel.control().orElseThrow().version().generation()).isGreaterThan(run.controlGeneration());
        }
        UUID intent = preparation.intentId();
        var selectedBudget = budget();
        assertThat(writer.assign(intent, first, budget()).status()).isEqualTo(Status.DENIED);
        assertThatThrownBy(() -> writer.requireAssigned(intent, first, selectedBudget))
                .isInstanceOf(AccessDeniedException.class);
        assertThat(count("ai_model_run_gateway_assignment")).isEqualTo(1);
    }

    @ParameterizedTest
    @ValueSource(strings = {"disabled", "generation"})
    void consumedOutcomeCannotAppendAcrossDisabledOrNewEnabledControl(String change) throws Exception {
        UUID correlation = assignedAndConsumed();
        var request = report(response("lab", true), correlation);
        if (change.equals("disabled")) {
            assertThat(kernel.disableControl(kernel.control().orElseThrow().version()).status())
                    .isEqualTo(Status.APPLIED);
        } else {
            advanceAndEnableControl();
            assertThat(registrations.current(first, budget())).isPresent();
        }
        String before = AiModelDispatchFixture.fingerprint(source);
        RunSnapshot beforeRun = current();
        assertThat(writer.append(request, first, budget()).status()).isEqualTo(Status.DENIED);
        assertThat(count("ai_model_run_outcome")).isZero();
        assertThat(AiModelDispatchFixture.fingerprint(source)).isEqualTo(before);
        assertThat(current()).isEqualTo(beforeRun);
    }

    private void advanceAndEnableControl() throws Exception {
        var pins = kernel.control().orElseThrow().pins().orElseThrow();
        var version = kernel
                .changeControl(kernel.control().orElseThrow().version(), pins)
                .value()
                .orElseThrow()
                .version();
        deployment = new Deployment(RuntimePeerRole.GATEWAY_RUN, version.generation(), deployment.imageDigest(),
                deployment.launch());
        assertThat(registrations.configure(deployment, budget())).isTrue();
        Instant now = AiRuntimeFixture.now(source);
        assertThat(registrations
                .observe(new Observation(deployment, first.subject(), 1, UUID.randomUUID(), now, now.plusSeconds(25)),
                        budget()))
                .isTrue();
        assertThat(kernel
                .observeControl(new ReadinessObservation(version, pins, 1, UUID.randomUUID(), now, now.plusSeconds(30)))
                .status()).isEqualTo(Status.APPLIED);
        assertThat(kernel.enableControl(version).status()).isEqualTo(Status.APPLIED);
    }

    @Test
    void unregisteredForeignGatewayCannotDiscoverAssignmentConflict() throws Exception {
        assertThat(writer.assign(preparation.intentId(), first, budget()).status()).isEqualTo(Status.APPLIED);
        var foreign = new RuntimePeer(RuntimePeerRole.GATEWAY_RUN,
                new RuntimeProxyCertificateClaims(first.subject().cluster(), first.subject().namespace(),
                        first.subject().serviceAccount(), "unregistered", UUID.randomUUID()));
        assertThat(registrations.current(foreign, budget())).isEmpty();
        UUID intent = preparation.intentId();
        var selectedBudget = budget();
        assertThat(writer.assign(intent, foreign, budget()).status()).isEqualTo(Status.DENIED);
        assertThatThrownBy(() -> writer.requireAssigned(intent, foreign, selectedBudget))
                .isInstanceOf(AccessDeniedException.class);
        writer.requireAssigned(intent, first, budget());
    }

    @ParameterizedTest
    @CsvSource({
            "ai_model_run_gateway_assignment,UPDATE",
            "ai_model_run_gateway_assignment,DELETE",
            "ai_model_run_gateway_assignment,TRUNCATE",
            "ai_model_run_outcome,UPDATE",
            "ai_model_run_outcome,DELETE",
            "ai_model_run_outcome,TRUNCATE"})
    void applicationDmlCannotRewriteDeleteOrTruncateEvidence(String table, String operation) throws Exception {
        UUID correlation = assignedAndConsumed();
        assertThat(writer.append(report(response("lab", true), correlation), first, budget()).status())
                .isEqualTo(Status.APPLIED);
        if (table.equals("ai_model_run_gateway_assignment") && operation.equals("TRUNCATE")) {
            // Remove this test-owned child table so this assertion reaches the assignment trigger, not a child-FK
            // refusal.
            try (var connection = source.getConnection(); var statement = connection.createStatement()) {
                statement.execute("DROP TABLE ai_model_run_outcome");
            }
        }
        String sql = switch (operation) {
            case "UPDATE" -> "UPDATE " + table + " SET "
                    + (table.equals("ai_model_run_outcome") ? "result_text" : "pod_name") + "='replacement'";
            case "DELETE" -> "DELETE FROM " + table;
            default -> "TRUNCATE " + table;
        };
        Throwable failure = org.assertj.core.api.Assertions.catchThrowable(() -> execute(sql));
        assertThat(sqlState(failure)).isEqualTo("55000");
        assertThat(count(table)).isEqualTo(1);
    }

    @Test
    void parentIntentRetentionCascadesBothImmutableChildren() throws Exception {
        UUID correlation = assignedAndConsumed();
        assertThat(writer.append(report(response("lab", true), correlation), first, budget()).status())
                .isEqualTo(Status.APPLIED);
        try (var connection = source.getConnection();
                var statement = connection.prepareStatement("DELETE FROM ai_model_run_intent WHERE uuid=?")) {
            statement.setObject(1, preparation.intentId());
            assertThat(statement.executeUpdate()).isEqualTo(1);
        }
        assertThat(count("ai_model_run_gateway_assignment")).isZero();
        assertThat(count("ai_model_run_outcome")).isZero();
        assertThat(AiModelDispatchFixture.reservedCalls(source, run.spec().runId())).isEqualTo(1);
    }

    @Test
    void parentLookupCannotBeDefeatedByShadowingTheSearchPath() throws Exception {
        assertThat(writer.assign(preparation.intentId(), first, budget()).status()).isEqualTo(Status.APPLIED);
        try (var connection = source.getConnection()) {
            connection.setAutoCommit(false);
            try {
                try (var statement = connection.createStatement()) {
                    statement.execute("CREATE TEMPORARY TABLE ai_model_run_intent(uuid UUID) ON COMMIT DROP");
                    statement.execute("SET LOCAL search_path=pg_temp,core");
                    Throwable failure = org.assertj.core.api.Assertions
                            .catchThrowable(
                                    () -> statement.execute("DELETE FROM core.ai_model_run_gateway_assignment"));
                    assertThat(sqlState(failure)).isEqualTo("55000");
                }
            } finally {
                connection.rollback();
            }
        }
        assertThat(count("ai_model_run_gateway_assignment")).isEqualTo(1);
    }

    @Test
    void actualFinalSqlTimeoutRollsBackOutcomeAndKeepsConsumedReservation() throws Exception {
        UUID correlation = assignedAndConsumed();
        var request = report(response("lab", true), correlation);
        String before = AiModelDispatchFixture.fingerprint(source);
        try {
            execute("CREATE FUNCTION core.outcome_delay() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN PERFORM pg_sleep(1); RETURN NEW; END $$");
            execute("CREATE TRIGGER outcome_delay AFTER INSERT ON ai_model_run_outcome FOR EACH ROW EXECUTE FUNCTION core.outcome_delay()");
            var operationBudget = AiRuntimeOperationBudget.start(Duration.ofMillis(500));
            Throwable failure = org.assertj.core.api.Assertions
                    .catchThrowable(() -> writer.append(request, first, operationBudget));
            assertThat(sqlState(failure)).isEqualTo("57014");
            assertThat(count("ai_model_run_outcome")).isZero();
            assertThat(AiModelDispatchFixture.fingerprint(source)).isEqualTo(before);
        } finally {
            execute("DROP TRIGGER IF EXISTS outcome_delay ON ai_model_run_outcome");
            execute("DROP FUNCTION IF EXISTS core.outcome_delay()");
        }
    }

    @Test
    void expiryBetweenMetadataAndFinalInsertDeniesWithoutMutatingAllowance() throws Exception {
        UUID correlation = assignedAndConsumed();
        var request = report(response("lab", true), correlation);
        Instant expiry = shortenRegistration();
        var reached = new java.util.concurrent.atomic.AtomicBoolean();
        var actualIntentLocked = new java.util.concurrent.atomic.AtomicBoolean();
        var repositoryProxy = new ProxyFactory(outcomeRepository);
        repositoryProxy.addAdvice((org.aopalliance.intercept.MethodInterceptor) call -> {
            Object result = call.proceed();
            if (call.getMethod().getName().equals("lockIntent") && ((java.util.Optional<?>) result).isPresent()) {
                actualIntentLocked.set(true);
            }
            if (call.getMethod().getName().equals("metadata") && actualIntentLocked.get()
                    && ((java.util.Optional<?>) result).isPresent()) {
                reached.set(true);
                org.awaitility.Awaitility
                        .await("Actual registration expired after successful metadata query")
                        .pollInSameThread()
                        .pollDelay(Duration.ZERO)
                        .pollInterval(Duration.ofMillis(5))
                        .atMost(Duration.ofSeconds(2))
                        .until(() -> !AiRuntimeFixture.now(source).isBefore(expiry));
            }
            return result;
        });
        var finalBoundary = transactionalWriter(runtimeRepository,
                (AiModelRunOutcomeRepository) repositoryProxy.getProxy());
        String before = AiModelDispatchFixture.fingerprint(source);
        assertThat(finalBoundary.append(request, first, budget()).status()).isEqualTo(Status.DENIED);
        assertThat(reached).isTrue();
        assertThat(count("ai_model_run_outcome")).isZero();
        assertThat(AiModelDispatchFixture.fingerprint(source)).isEqualTo(before);
    }

    @Test
    void expiryAfterActualInsertRollsBackWhenReceiptIsNoLongerCurrent() throws Exception {
        UUID correlation = assignedAndConsumed();
        var request = report(response("lab", true), correlation);
        String before = AiModelDispatchFixture.fingerprint(source);
        try {
            execute("CREATE SEQUENCE core.outcome_insert_witness");
            execute("CREATE FUNCTION core.outcome_registration_delay() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN PERFORM nextval('core.outcome_insert_witness'); PERFORM pg_sleep(1.2); RETURN NEW; END $$");
            execute("CREATE TRIGGER outcome_registration_delay AFTER INSERT ON ai_model_run_outcome FOR EACH ROW EXECUTE FUNCTION core.outcome_registration_delay()");
            shortenRegistration();
            var selectedBudget = budget();
            assertThatThrownBy(() -> writer.append(request, first, selectedBudget))
                    .isInstanceOf(IllegalStateException.class)
                    .hasMessage("Model outcome transition unavailable");
            try (var connection = source.getConnection();
                    var statement = connection.createStatement();
                    var rows = statement.executeQuery("SELECT is_called FROM core.outcome_insert_witness")) {
                assertThat(rows.next()).isTrue();
                assertThat(rows.getBoolean(1)).as("Actual insert trigger reached before rollback").isTrue();
            }
            assertThat(count("ai_model_run_outcome")).isZero();
            assertThat(AiModelDispatchFixture.fingerprint(source)).isEqualTo(before);
        } finally {
            execute("DROP TRIGGER IF EXISTS outcome_registration_delay ON ai_model_run_outcome");
            execute("DROP FUNCTION IF EXISTS core.outcome_registration_delay()");
            execute("DROP SEQUENCE IF EXISTS core.outcome_insert_witness");
        }
    }

    private Instant shortenRegistration() throws Exception {
        Instant now = AiRuntimeFixture.now(source);
        Instant expiry = now.plusSeconds(1);
        assertThat(registrations
                .observe(new Observation(deployment, first.subject(), 2, UUID.randomUUID(), now, expiry), budget()))
                .isTrue();
        return expiry;
    }

    @ParameterizedTest
    @ValueSource(strings = {"none", "model", "tokens", "expiry"})
    void resultValidationDoesNotHoldGlobalControlAndRechecksMetadata(String drift) throws Exception {
        UUID correlation = assignedAndConsumed();
        var request = report(response("lab", true), correlation);
        var enteredValidation = new java.util.concurrent.CountDownLatch(1);
        var returnValidation = new java.util.concurrent.CountDownLatch(1);
        var executor = Executors.newSingleThreadExecutor();
        try {
            var result = executor.submit(() -> {
                try (var validation = org.mockito.Mockito
                        .mockStatic(com.otilm.core.model.ai.AiModelRunResult.class,
                                org.mockito.Mockito.CALLS_REAL_METHODS)) {
                    validation
                            .when(() -> com.otilm.core.model.ai.AiModelRunResult
                                    .validate(org.mockito.ArgumentMatchers.any(byte[].class),
                                            org.mockito.ArgumentMatchers.eq("lab"),
                                            org.mockito.ArgumentMatchers.eq(32)))
                            .thenAnswer(call -> {
                                enteredValidation.countDown();
                                assertThat(returnValidation.await(2, TimeUnit.SECONDS)).isTrue();
                                return call.callRealMethod();
                            });
                    return writer.append(request, first, budget());
                }
            });
            assertThat(enteredValidation.await(1, TimeUnit.SECONDS)).isTrue();
            try (var connection = source.getConnection()) {
                connection.setAutoCommit(false);
                try (var statement = connection.createStatement()) {
                    Throwable failure = org.assertj.core.api.Assertions.catchThrowable(() -> {
                        try (var rows = statement
                                .executeQuery(
                                        "SELECT generation FROM ai_runtime_control WHERE id=1 FOR UPDATE NOWAIT")) {
                            assertThat(rows.next()).isTrue();
                        }
                    });
                    assertThat(failure)
                            .as("Global control lock during paused validation SQLSTATE=%s", sqlState(failure))
                            .isNull();
                }
                if (!drift.equals("none")) {
                    String assignment = switch (drift) {
                        case "model" -> "model_identifier='other-model'";
                        case "tokens" -> "output_tokens=1";
                        default -> "expires_at=expires_at+INTERVAL '1 second'";
                    };
                    // Explicit local database fault injection: currently no intent metadata immutability trigger
                    // exists.
                    try (var statement = connection
                            .prepareStatement("UPDATE ai_model_run_intent SET " + assignment + " WHERE uuid=?")) {
                        statement.setObject(1, preparation.intentId());
                        assertThat(statement.executeUpdate()).isEqualTo(1);
                    }
                }
                connection.commit();
            }
            String afterFault = AiModelDispatchFixture.fingerprint(source);
            returnValidation.countDown();
            var outcome = result.get(3, TimeUnit.SECONDS);
            assertThat(outcome.status()).isEqualTo(drift.equals("none") ? Status.APPLIED : Status.DENIED);
            assertThat(count("ai_model_run_outcome")).isEqualTo(drift.equals("none") ? 1 : 0);
            assertThat(AiModelDispatchFixture.fingerprint(source)).isEqualTo(afterFault);
            assertThat(AiModelDispatchFixture.reservedCalls(source, run.spec().runId())).isEqualTo(1);
            assertThat(AiModelDispatchFixture.reservedTokens(source, run.spec().runId(), false)).isEqualTo(32);
        } finally {
            returnValidation.countDown();
            executor.shutdownNow();
            assertThat(executor.awaitTermination(5, TimeUnit.SECONDS)).isTrue();
        }
    }

    private UUID assignedAndConsumed() {
        assertThat(writer.assign(preparation.intentId(), first, budget()).status()).isEqualTo(Status.APPLIED);
        return consumeFixture().gatewayCorrelation();
    }

    private com.otilm.core.model.ai.AiModelDispatchState.ResolvedDispatch consumeFixture() {
        return dispatches
                .consumeRun(new RunRedemption(preparation.intentId(), expected(current()), claim.binding(), model,
                        preparation.payload().sha256(), preparation.expiresAt(), UUID.randomUUID()), budget())
                .orElseThrow();
    }

    private OutcomeRequest report(byte[] response, UUID correlation) throws Exception {
        return new AiRuntimeGatewayWire()
                .readOutcome(new ObjectMapper().writeValueAsBytes(outcomeNode(response, correlation)));
    }

    private ObjectNode outcomeNode(byte[] response, UUID correlation) throws Exception {
        var mapper = new ObjectMapper();
        var binding = new RunBinding(claim.binding().runId(), claim.binding().attemptId(),
                UUID.fromString(claim.binding().workload().podUid()), claim.binding().claimId(),
                claim.binding().fence(), preparation.expiresAt());
        var envelope = new RunDispatchEnvelope(1, preparation.intentId(), preparation.payload().sha256(), binding);
        var node = mapper
                .createObjectNode()
                .put("protocolVersion", 1)
                .put("kind", "run-outcome")
                .put("intentId", preparation.intentId().toString())
                .put("gatewayCorrelation", correlation.toString());
        node.set("binding", mapper.readTree(new ProtocolCodec().writeDispatch(envelope)).get("binding"));
        node
                .put("payloadSha256", preparation.payload().sha256())
                .put("transportCode", response == null ? "UNKNOWN" : "HTTP_200");
        if (response == null) {
            node.putNull("responseBase64").putNull("responseSha256").put("responseByteCount", 0);
        } else {
            node
                    .put("responseBase64", Base64.getEncoder().encodeToString(response))
                    .put("responseSha256",
                            HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(response)))
                    .put("responseByteCount", response.length);
        }
        node.putObject("usage").put("kind", "unknown");
        return node;
    }

    private static byte[] response(String model, boolean usage) {
        return ("{\"model\":\"" + model
                + "\",\"choices\":[{\"index\":0,\"finish_reason\":\"stop\",\"message\":{\"role\":\"assistant\",\"content\":\"assistant-result\"}}]"
                + (usage ? ",\"usage\":{\"prompt_tokens\":1,\"completion_tokens\":2,\"total_tokens\":3}" : "") + "}")
                .getBytes(StandardCharsets.UTF_8);
    }

    private long count(String table) throws Exception {
        if (!java.util.Set.of("ai_model_run_outcome", "ai_model_run_gateway_assignment").contains(table)) {
            throw new IllegalArgumentException();
        }
        try (var connection = source.getConnection();
                var statement = connection.createStatement();
                var rows = statement.executeQuery("SELECT count(*) FROM " + table)) {
            assertThat(rows.next()).isTrue();
            return rows.getLong(1);
        }
    }

    private String outcomeFingerprint() throws Exception {
        try (var connection = source.getConnection();
                var statement = connection.createStatement();
                var rows = statement.executeQuery("SELECT row_to_json(o)::text FROM ai_model_run_outcome o")) {
            assertThat(rows.next()).isTrue();
            return HexFormat
                    .of()
                    .formatHex(MessageDigest
                            .getInstance("SHA-256")
                            .digest(rows.getString(1).getBytes(StandardCharsets.UTF_8)));
        }
    }

    private void execute(String sql) throws Exception {
        try (var connection = source.getConnection(); var statement = connection.createStatement()) {
            statement.execute(sql);
        }
    }

    private static String sqlState(Throwable failure) {
        for (Throwable cause = failure; cause != null; cause = cause.getCause()) {
            if (cause instanceof SQLException sql) {
                return sql.getSQLState();
            }
        }
        return "NO_SQL_STATE";
    }

    @ParameterizedTest
    @ValueSource(strings = {"assignment", "same-report", "conflicting-report"})
    void coreReplicasSerializeWithTwoActualBackendWaiters(String mode) throws Exception {
        boolean reporting = !mode.equals("assignment");
        UUID correlation = reporting ? assignedAndConsumed() : UUID.randomUUID();
        OutcomeRequest one = report(response("lab", true), correlation);
        byte[] otherResponse = new String(response("lab", true), StandardCharsets.UTF_8)
                .replace("assistant-result", "different-result")
                .getBytes(StandardCharsets.UTF_8);
        OutcomeRequest two = mode.equals("conflicting-report") ? report(otherResponse, correlation) : one;
        var pidOne = new AtomicInteger();
        var pidTwo = new AtomicInteger();
        var actualGraph = new java.util.concurrent.atomic.AtomicReference<java.util.Map<Integer, java.util.List<Integer>>>(
                java.util.Map.of());
        var replicaOne = replica(pidOne);
        var replicaTwo = replica(pidTwo);
        var executor = Executors.newFixedThreadPool(2);
        try (var holder = source.getConnection(); var observer = source.getConnection()) {
            holder.setAutoCommit(false);
            int holderPid;
            try (var statement = holder.createStatement();
                    var rows = statement.executeQuery("SELECT pg_backend_pid()")) {
                assertThat(rows.next()).isTrue();
                holderPid = rows.getInt(1);
            }
            try (var statement = holder.createStatement();
                    var rows = statement
                            .executeQuery("SELECT generation FROM ai_runtime_control WHERE id=1 FOR UPDATE")) {
                assertThat(rows.next()).isTrue();
            }
            var resultOne = executor
                    .submit(() -> reporting
                            ? replicaOne.append(one, first, budget())
                            : replicaOne.assign(preparation.intentId(), first, budget()));
            var resultTwo = executor
                    .submit(() -> reporting
                            ? replicaTwo.append(two, first, budget())
                            : replicaTwo.assign(preparation.intentId(), second, budget()));
            try {
                org.awaitility.Awaitility
                        .await("Both exact owned backend lock waiters")
                        .pollInSameThread()
                        .pollDelay(Duration.ZERO)
                        .pollInterval(Duration.ofMillis(2))
                        .atMost(Duration.ofMillis(800))
                        .until(() -> {
                            if (pidOne.get() <= 0 || pidTwo.get() <= 0 || pidOne.get() == pidTwo.get()
                                    || pidOne.get() == holderPid || pidTwo.get() == holderPid) {
                                return false;
                            }
                            var graph = blockingGraph(observer, holderPid, pidOne.get(), pidTwo.get());
                            actualGraph.set(graph);
                            return graph.keySet().containsAll(java.util.Set.of(holderPid, pidOne.get(), pidTwo.get()))
                                    && graph.get(holderPid).isEmpty()
                                    && ownedPathToHolder(graph, holderPid, pidOne.get(), pidTwo.get())
                                    && ownedPathToHolder(graph, holderPid, pidTwo.get(), pidOne.get());
                        });
            } catch (org.awaitility.core.ConditionTimeoutException failure) {
                throw new AssertionError(
                        "Both physical database writers lacked owned blocking paths; exactOwnedBlockerGraph="
                                + actualGraph.get() + "; holder=" + holderPid + "; first=" + pidOne.get() + "; second="
                                + pidTwo.get() + "; firstDone=" + resultOne.isDone() + "; secondDone="
                                + resultTwo.isDone(),
                        failure);
            }
            assertThat(pidOne.get()).isPositive().isNotEqualTo(holderPid).isNotEqualTo(pidTwo.get());
            assertThat(pidTwo.get()).isPositive().isNotEqualTo(holderPid);
            holder.rollback();
            var outcomeOne = resultOne.get(4, TimeUnit.SECONDS);
            var outcomeTwo = resultTwo.get(4, TimeUnit.SECONDS);
            Status other = mode.equals("same-report") ? Status.REPLAY : Status.CONFLICT;
            assertThat(java.util.List.of(outcomeOne.status(), outcomeTwo.status()))
                    .containsExactlyInAnyOrder(Status.APPLIED, other);
            if (mode.equals("same-report")) {
                assertThat(outcomeOne.value()).isEqualTo(outcomeTwo.value());
            }
            if (!reporting) {
                RuntimePeer winner = outcomeOne.status() == Status.APPLIED ? first : second;
                RuntimePeer loser = outcomeOne.status() == Status.APPLIED ? second : first;
                UUID intent = preparation.intentId();
                var selectedBudget = budget();
                writer.requireAssigned(intent, winner, budget());
                assertThatThrownBy(() -> writer.requireAssigned(intent, loser, selectedBudget))
                        .isInstanceOf(AccessDeniedException.class);
            }
            assertThat(count(reporting ? "ai_model_run_outcome" : "ai_model_run_gateway_assignment")).isEqualTo(1);
        } finally {
            executor.shutdownNow();
            assertThat(executor.awaitTermination(5, TimeUnit.SECONDS)).isTrue();
        }
    }

    private AiModelRunOutcomeWriter replica(AtomicInteger pid) {
        var repositoryProxy = new ProxyFactory(runtimeRepository);
        repositoryProxy.addAdvice((org.aopalliance.intercept.MethodInterceptor) call -> {
            if (call.getMethod().getName().equals("lockControl")) {
                pid
                        .set(((Number) entityManager.createNativeQuery("SELECT pg_backend_pid()").getSingleResult())
                                .intValue());
            }
            return call.proceed();
        });
        return transactionalWriter((AiRuntimeRepository) repositoryProxy.getProxy(), outcomeRepository);
    }

    private AiModelRunOutcomeWriter transactionalWriter(AiRuntimeRepository runtime,
            AiModelRunOutcomeRepository outcomes) {
        var writerProxy = new ProxyFactory(new AiModelRunOutcomeWriter(runtime, outcomes));
        writerProxy.setProxyTargetClass(true);
        writerProxy
                .addAdvice(new TransactionInterceptor((org.springframework.transaction.TransactionManager) transactions,
                        new AnnotationTransactionAttributeSource()));
        return (AiModelRunOutcomeWriter) writerProxy.getProxy();
    }

    private static boolean ownedPathToHolder(java.util.Map<Integer, java.util.List<Integer>> graph, int holder,
            int writer, int otherWriter) {
        var blockers = graph.getOrDefault(writer, java.util.List.of());
        return !blockers.isEmpty() && java.util.Set.of(holder, otherWriter).containsAll(blockers)
                && (blockers.contains(holder) || blockers.contains(otherWriter)
                        && graph.getOrDefault(otherWriter, java.util.List.of()).contains(holder));
    }

    private static java.util.Map<Integer, java.util.List<Integer>> blockingGraph(java.sql.Connection observer,
            int holder, int first, int second) throws Exception {
        try (var statement = observer
                .prepareStatement("SELECT pid,pg_blocking_pids(pid) FROM pg_stat_activity WHERE pid IN (?,?,?)")) {
            statement.setInt(1, holder);
            statement.setInt(2, first);
            statement.setInt(3, second);
            try (var rows = statement.executeQuery()) {
                var graph = new java.util.HashMap<Integer, java.util.List<Integer>>();
                while (rows.next()) {
                    var raw = (Integer[]) rows.getArray(2).getArray();
                    graph.put(rows.getInt(1), java.util.List.of(raw));
                }
                return java.util.Map.copyOf(graph);
            }
        }
    }

}
