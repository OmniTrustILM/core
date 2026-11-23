package com.otilm.core.integration.service;

import com.otilm.ai.runtime.protocol.ManagementAction;
import com.otilm.core.model.ai.AiModelDispatchState.ConnectionVersion;
import com.otilm.core.model.ai.AiModelDispatchState.ManagementPreparation;
import com.otilm.core.model.ai.AiModelDispatchState.ManagementRedemption;
import com.otilm.core.model.ai.AiModelManagementSession.Spec;
import com.otilm.core.model.ai.AiRuntimeManagementGatewayState.Deployment;
import com.otilm.core.model.ai.AiRuntimeManagementGatewayState.Observation;
import com.otilm.core.model.ai.AiRuntimeManagementGatewayState.Pins;
import com.otilm.core.model.ai.AiRuntimeState.LaunchSpec;
import com.otilm.core.model.ai.AiRuntimeState.Status;
import com.otilm.core.security.ai.RuntimePeer;
import com.otilm.core.security.ai.RuntimePeerRole;
import com.otilm.core.security.ai.RuntimeProxyCertificateClaims;
import com.otilm.core.service.ai.AiFeatureGate;
import com.otilm.core.service.ai.AiRuntimeJdbcBudget;
import com.otilm.core.service.ai.AiRuntimeOperationBudget;
import com.otilm.core.service.writer.ai.AiModelDispatchWriter;
import com.otilm.core.service.writer.ai.AiModelManagementGatewayWriter;
import com.otilm.core.service.writer.ai.AiModelManagementSessionWriter;
import com.otilm.core.service.writer.ai.AiRuntimeManagementGatewayWriter;
import com.otilm.core.util.AiModelDispatchFixture;
import com.otilm.core.util.AiRuntimeFixture;
import com.otilm.core.util.ai.BaseAiSpringBootTest;
import java.lang.reflect.Proxy;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.time.Instant;
import java.util.UUID;
import java.util.function.Function;
import java.util.function.Supplier;
import javax.sql.DataSource;
import org.aspectj.lang.ProceedingJoinPoint;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.access.AccessDeniedException;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/** Real PostgreSQL final native management gates. Fixture facts are not real CONNECT or workload attestation. */
class AiModelManagementNativeITest extends BaseAiSpringBootTest {
    @Autowired
    private DataSource source;
    @Autowired
    private org.springframework.transaction.PlatformTransactionManager transactions;
    @Autowired
    private AiRuntimeJdbcBudget jdbcBudget;
    @Autowired
    private com.otilm.core.dao.repository.ai.AiModelDispatchRepository models;
    @jakarta.persistence.PersistenceContext
    private jakarta.persistence.EntityManager entityManager;
    @Autowired
    private AiModelDispatchWriter writer;
    @Autowired
    private AiModelManagementSessionWriter sessions;
    @Autowired
    private AiRuntimeManagementGatewayWriter registry;
    @Autowired
    private AiModelManagementGatewayWriter assignments;
    @Autowired
    private com.otilm.core.service.writer.ai.AiModelManagementOutcomeWriter outcomes;
    private final com.otilm.core.service.ai.AiRuntimeManagementWire wire = new com.otilm.core.service.ai.AiRuntimeManagementWire();
    private UUID actor, session, intent, requestKey;
    private ConnectionVersion model;
    private Instant expiry;
    private RuntimePeer peer;
    private ManagementPreparation preparation;
    private Deployment deployment;

    @BeforeEach
    void setup() throws Exception {
        AiModelDispatchFixture.drop(source);
        AiRuntimeFixture.install(source);
        execute("DELETE FROM ai_runtime_control");
        actor = UUID.randomUUID();
        session = UUID.randomUUID();
        intent = UUID.randomUUID();
        requestKey = UUID.randomUUID();
        model = AiModelDispatchFixture.approvedModel(source);
        expiry = AiRuntimeFixture.now(source).plusSeconds(30);
        var spec = new Spec(session, actor, model, ManagementAction.CONNECTION_CHECK, expiry, 3, 96);
        assertThat(sessions.create(spec, budget()).status()).isEqualTo(Status.APPLIED);
        preparation = new ManagementPreparation(intent, requestKey, actor, session, spec.action(), model,
                AiModelDispatchFixture.payload(32, "Core fixed probe"), 32, expiry);
        assertThat(writer.prepareManagement(preparation, budget()).status()).isEqualTo(Status.APPLIED);
        var pins = new Pins("sha256:" + "a".repeat(64), new LaunchSpec("cluster-one", "ai-proof", "namespace-one",
                "management", "account-one", "sha256:" + "b".repeat(64), "sandbox"));
        deployment = registry.configure(0, pins, budget()).value().orElseThrow();
        peer = new RuntimePeer(RuntimePeerRole.GATEWAY_MANAGEMENT, new RuntimeProxyCertificateClaims("cluster-one",
                "ai-proof", "management", "gateway", UUID.randomUUID()));
        observe(peer, Duration.ofSeconds(5));
    }

    @Test
    void exactAssignedCurrentManagementGatewayConsumesOnceWithoutAnyRunOrActivation() throws Exception {
        assertThat(assignments.assign(intent, peer, budget()).status()).isEqualTo(Status.APPLIED);
        assignments.requireAssigned(intent, peer, budget());
        var q = redemption(intent, UUID.randomUUID());
        var result = writer.consumeManagement(q, actor, peer, budget());
        assertThat(result).isPresent();
        assertThat(result.orElseThrow().intentId()).isEqualTo(intent);
        assertThat(result.orElseThrow().payload()).isEqualTo(preparation.payload());
        assertThat(writer.consumeManagement(q, actor, peer, budget())).isEmpty();
        assignments.requireAssigned(intent, peer, budget());
        assertThat(count("ai_runtime_control")).isZero();
        assertThat(count("ai_runtime_run")).isZero();
        assertThat(AiModelDispatchFixture.reservedTokens(source, session, true)).isEqualTo(32);
    }

    @Test
    void roleOnlyAndCopiedPreparedEnvelopeWithoutAssignmentCannotConsume() throws Exception {
        String before = AiModelDispatchFixture.fingerprint(source);
        assertThat(writer.consumeManagement(redemption(intent, UUID.randomUUID()), actor, peer, budget())).isEmpty();
        assertThat(AiModelDispatchFixture.fingerprint(source)).isEqualTo(before);
        assertThatThrownBy(() -> assignments.requireAssigned(intent, peer, budget()))
                .isInstanceOf(AccessDeniedException.class);
    }

    @Test
    void firstAssignmentIsImmutableAndExactReplayIsStable() throws Exception {
        assertThat(assignments.assign(intent, peer, budget()).status()).isEqualTo(Status.APPLIED);
        assertThat(assignments.assign(intent, peer, budget()).status()).isEqualTo(Status.REPLAY);
        var other = otherPeer();
        observe(other, Duration.ofSeconds(5));
        assertThat(assignments.assign(intent, other, budget()).status()).isEqualTo(Status.CONFLICT);
        assertThat(writer.consumeManagement(redemption(intent, UUID.randomUUID()), actor, other, budget())).isEmpty();
        assertThat(writer.consumeManagement(redemption(intent, UUID.randomUUID()), actor, peer, budget())).isPresent();
    }

    @ParameterizedTest
    @ValueSource(strings = {"revoke", "disable", "expiry", "foreign", "wrong-role"})
    void finalConsumeDeniesActualCurrentMembershipLossEvenAfterEarlierAssignmentCheck(String changed) throws Exception {
        if (changed.equals("expiry")) {
            assertThat(registry.configure(deployment.revision(), deployment.pins(), budget()).status())
                    .isEqualTo(Status.APPLIED);
            deployment = new Deployment(deployment.revision() + 1, deployment.pins());
            observe(peer, Duration.ofMillis(200));
        }
        assertThat(assignments.assign(intent, peer, budget()).status()).isEqualTo(Status.APPLIED);
        assignments.requireAssigned(intent, peer, budget());
        RuntimePeer supplied = peer;
        switch (changed) {
            case "revoke" -> registry.revoke(peer, budget());
            case "disable" -> registry.disable(deployment.revision(), budget());
            case "expiry" -> org.awaitility.Awaitility
                    .await()
                    .pollInSameThread()
                    .pollDelay(Duration.ZERO)
                    .pollInterval(Duration.ofMillis(2))
                    .atMost(Duration.ofSeconds(1))
                    .until(() -> registry.current(peer, budget()).isEmpty());
            case "foreign" -> {
                supplied = otherPeer();
                observe(supplied, Duration.ofSeconds(5));
            }
            case "wrong-role" -> supplied = new RuntimePeer(RuntimePeerRole.GATEWAY_RUN, peer.subject());
            default -> throw new AssertionError("Unknown fixture case");
        }
        String before = AiModelDispatchFixture.fingerprint(source);
        assertThat(writer.consumeManagement(redemption(intent, UUID.randomUUID()), actor, supplied, budget()))
                .isEmpty();
        assertThat(AiModelDispatchFixture.fingerprint(source)).isEqualTo(before);
    }

    @Test
    void actorMustBeTheOneFreshlyAuthorizedBeforeReserveAndFinalConsume() throws Exception {
        var fresh = new ManagementPreparation(UUID.randomUUID(), UUID.randomUUID(), actor, session,
                preparation.action(), model, preparation.payload(), 32, expiry);
        String before = AiModelDispatchFixture.fingerprint(source);
        assertThat(writer.prepareManagement(fresh, UUID.randomUUID(), budget()).status()).isEqualTo(Status.DENIED);
        assertThat(AiModelDispatchFixture.fingerprint(source)).isEqualTo(before);
        assertThat(writer.prepareManagement(fresh, actor, budget()).status()).isEqualTo(Status.APPLIED);
        assertThat(assignments.assign(intent, peer, budget()).status()).isEqualTo(Status.APPLIED);
        assertThat(writer.consumeManagement(redemption(intent, UUID.randomUUID()), UUID.randomUUID(), peer, budget()))
                .isEmpty();
        assertThat(writer.consumeManagement(redemption(intent, UUID.randomUUID()), actor, peer, budget())).isPresent();
    }

    @ParameterizedTest
    @ValueSource(strings = {
            "UPDATE ai_model_management_gateway_assignment SET pod_name='foreign'",
            "DELETE FROM ai_model_management_gateway_assignment",
            "TRUNCATE ai_model_management_gateway_assignment",
            "TRUNCATE ai_model_management_gateway_assignment CASCADE"})
    void assignmentCannotBeRewrittenRemovedOrTruncated(String sql) throws Exception {
        assertThat(assignments.assign(intent, peer, budget()).status()).isEqualTo(Status.APPLIED);
        assertThatThrownBy(() -> execute(sql))
                .isInstanceOf(java.sql.SQLException.class)
                .extracting(e -> ((java.sql.SQLException) e).getSQLState())
                .isIn(sql.equals("TRUNCATE ai_model_management_gateway_assignment")
                        ? new String[]{"55000", "0A000"}
                        : new String[]{"55000"});
        assignments.requireAssigned(intent, peer, budget());
    }

    @Test
    void exactOutcomeReplayRetainsOnePositiveVersionAndNeverRefundsAllowance() throws Exception {
        UUID correlation = consumeForOutcome();
        var q = outcome(correlation, provider("SYNTHETIC_TEXT_CANARY"));
        var first = outcomes.append(q, peer, budget());
        assertThat(first.status()).isEqualTo(Status.APPLIED);
        var receipt = first.value().orElseThrow();
        assertThat(receipt.intentId()).isEqualTo(intent);
        assertThat(receipt.outcomeSha256()).isEqualTo(q.outcomeSha256());
        assertThat(receipt.resultVersion()).isPositive();
        var repeat = outcomes.append(q, peer, budget());
        assertThat(repeat.status()).isEqualTo(Status.REPLAY);
        assertThat(repeat.value()).contains(receipt);
        assertThat(outcomes.append(outcome(correlation, provider("CONFLICT_CANARY")), peer, budget()).status())
                .isEqualTo(Status.CONFLICT);
        assertThat(AiModelDispatchFixture.reservedTokens(source, session, true)).isEqualTo(32);
        var result = outcomes.read(session, intent, actor, budget()).orElseThrow();
        assertThat(result.text()).isEqualTo("SYNTHETIC_TEXT_CANARY");
        assertThat(result.receipt()).isEqualTo(receipt);
        assertThat(outcomes.read(session, intent, UUID.randomUUID(), budget())).isEmpty();
        assertThat(outcomes.read(UUID.randomUUID(), intent, actor, budget())).isEmpty();
    }

    @ParameterizedTest
    @ValueSource(strings = {"closed", "expired"})
    void consumedLateEvidenceCanAppendWithoutReopeningSessionOrReleasingAllowance(String state) throws Exception {
        if (state.equals("expired")) {
            // A new finite fixture session, never an unversioned edit of an immutable stored deadline.
            session = UUID.randomUUID();
            intent = UUID.randomUUID();
            expiry = AiRuntimeFixture.now(source).plusMillis(600);
            var spec = new Spec(session, actor, model, ManagementAction.CONNECTION_CHECK, expiry, 3, 96);
            assertThat(sessions.create(spec, budget()).status()).isEqualTo(Status.APPLIED);
            preparation = new ManagementPreparation(intent, UUID.randomUUID(), actor, session, spec.action(), model,
                    preparation.payload(), 32, expiry);
            assertThat(writer.prepareManagement(preparation, budget()).status()).isEqualTo(Status.APPLIED);
        }
        UUID correlation = consumeForOutcome();
        if (state.equals("closed")) {
            assertThat(sessions.close(session, budget()).status()).isEqualTo(Status.APPLIED);
        } else {
            org.awaitility.Awaitility
                    .await("Actual immutable session expiry")
                    .pollInSameThread()
                    .pollDelay(Duration.ZERO)
                    .pollInterval(Duration.ofMillis(2))
                    .atMost(Duration.ofSeconds(1))
                    .until(() -> !AiRuntimeFixture.now(source).isBefore(expiry));
        }
        String before = AiModelDispatchFixture.fingerprint(source);
        assertThat(outcomes.append(outcome(correlation, provider("late")), peer, budget()).status())
                .isEqualTo(Status.APPLIED);
        assertThat(AiModelDispatchFixture.fingerprint(source)).isEqualTo(before);
        assertThat(AiModelDispatchFixture.reservedTokens(source, session, true)).isEqualTo(32);
        assertThat(outcomes.read(session, intent, actor, budget())).isEmpty();
    }

    @Test
    void parentIntentRetentionCascadesWithoutPermittingDirectEvidenceDeletion() throws Exception {
        UUID correlation = consumeForOutcome();
        assertThat(outcomes.append(outcome(correlation, provider("retained")), peer, budget()).status())
                .isEqualTo(Status.APPLIED);
        String directDelete = "DELETE FROM ai_model_management_outcome WHERE intent_uuid='" + intent + "'";
        assertThatThrownBy(() -> execute(directDelete))
                .isInstanceOf(java.sql.SQLException.class)
                .extracting(e -> ((java.sql.SQLException) e).getSQLState())
                .isEqualTo("55000");
        assertThat(count("ai_model_management_outcome")).isEqualTo(1);
        assertThat(count("ai_model_management_gateway_assignment")).isEqualTo(1);
        execute("DELETE FROM ai_model_management_intent WHERE uuid='" + intent + "'");
        assertThat(count("ai_model_management_outcome")).isZero();
        assertThat(count("ai_model_management_gateway_assignment")).isZero();
        assertThat(outcomes.read(session, intent, actor, budget())).isEmpty();
        assertThat(AiModelDispatchFixture.reservedTokens(source, session, true)).isEqualTo(32);
    }

    @ParameterizedTest
    @ValueSource(strings = {"unknown", "malformed", "missing-usage"})
    void unknownOrUnusableUsageRetainsTheWholeReservation(String kind) throws Exception {
        UUID correlation = consumeForOutcome();
        byte[] response = kind.equals("unknown")
                ? null
                : kind.equals("malformed")
                        ? "INVALID_CANARY".getBytes(StandardCharsets.UTF_8)
                        : "{\"model\":\"lab\",\"choices\":[{\"index\":0,\"message\":{\"role\":\"assistant\",\"content\":\"OK\"},\"finish_reason\":\"stop\"}]}"
                                .getBytes(StandardCharsets.UTF_8);
        assertThat(outcomes.append(outcome(correlation, response), peer, budget()).status()).isEqualTo(Status.APPLIED);
        assertThat(AiModelDispatchFixture.reservedTokens(source, session, true)).isEqualTo(32);
        try (var c = source.getConnection();
                var q = c.createStatement();
                var rows = q
                        .executeQuery(
                                "SELECT prompt_tokens,completion_tokens,total_tokens FROM ai_model_management_outcome")) {
            assertThat(rows.next()).isTrue();
            assertThat(rows.getObject(1)).isNull();
            assertThat(rows.getObject(2)).isNull();
            assertThat(rows.getObject(3)).isNull();
        }
    }

    @Test
    void foreignSenderOrCorrelationCannotAppendCopiedEvidence() throws Exception {
        UUID correlation = consumeForOutcome();
        var other = otherPeer();
        observe(other, Duration.ofSeconds(5));
        var q = outcome(correlation, provider("OK"));
        assertThat(outcomes.append(q, other, budget()).status()).isEqualTo(Status.DENIED);
        assertThat(outcomes.append(outcome(UUID.randomUUID(), provider("OK")), peer, budget()).status())
                .isEqualTo(Status.DENIED);
        assertThat(outcomes.append(q, peer, budget()).status()).isEqualTo(Status.APPLIED);
    }

    @ParameterizedTest
    @ValueSource(strings = {
            "UPDATE ai_model_management_outcome SET result_text='foreign'",
            "DELETE FROM ai_model_management_outcome",
            "TRUNCATE ai_model_management_outcome"})
    void protectedOutcomeCannotBeRewrittenRemovedOrTruncated(String sql) throws Exception {
        UUID correlation = consumeForOutcome();
        assertThat(outcomes.append(outcome(correlation, provider("OK")), peer, budget()).status())
                .isEqualTo(Status.APPLIED);
        assertThatThrownBy(() -> execute(sql))
                .isInstanceOf(java.sql.SQLException.class)
                .extracting(e -> ((java.sql.SQLException) e).getSQLState())
                .isEqualTo("55000");
    }

    private UUID consumeForOutcome() {
        assertThat(assignments.assign(intent, peer, budget()).status()).isEqualTo(Status.APPLIED);
        UUID correlation = UUID.randomUUID();
        assertThat(writer.consumeManagement(redemption(intent, correlation), actor, peer, budget())).isPresent();
        return correlation;
    }

    private byte[] provider(String text) {
        return ("{\"model\":\"lab\",\"choices\":[{\"index\":0,\"message\":{\"role\":\"assistant\",\"content\":\"" + text
                + "\"},\"finish_reason\":\"stop\"}],\"usage\":{\"prompt_tokens\":2,\"completion_tokens\":1,\"total_tokens\":3}}")
                .getBytes(StandardCharsets.UTF_8);
    }

    private com.otilm.core.service.ai.AiRuntimeManagementWire.OutcomeRequest outcome(UUID correlation, byte[] response)
            throws Exception {
        var json = new com.fasterxml.jackson.databind.ObjectMapper();
        var envelope = new com.otilm.ai.runtime.protocol.ManagementDispatchEnvelope(1, intent,
                preparation.payload().sha256(), new com.otilm.ai.runtime.protocol.ManagementBinding(actor, session,
                        model.id(), model.configuration(), preparation.action(), expiry));
        var document = json
                .createObjectNode()
                .put("protocolVersion", 1)
                .put("kind", "management-outcome")
                .put("intentId", intent.toString())
                .put("gatewayCorrelation", correlation.toString());
        document
                .set("binding",
                        json
                                .readTree(new com.otilm.ai.runtime.protocol.ProtocolCodec().writeDispatch(envelope))
                                .get("binding"));
        document
                .put("payloadSha256", preparation.payload().sha256())
                .put("transportCode", response == null ? "UNKNOWN" : "HTTP_200");
        if (response == null) {
            document.putNull("responseBase64").putNull("responseSha256").put("responseByteCount", 0);
        } else {
            document
                    .put("responseBase64", java.util.Base64.getEncoder().encodeToString(response))
                    .put("responseSha256", com.otilm.ai.runtime.protocol.PayloadFingerprint.sha256(response))
                    .put("responseByteCount", response.length);
        }
        document.putObject("usage").put("kind", "unknown");
        return wire.readOutcome(json.writeValueAsBytes(document));
    }

    @Test
    void aNewDeploymentNeverRebindsAnOldImmutableAssignment() throws Exception {
        assertThat(assignments.assign(intent, peer, budget()).status()).isEqualTo(Status.APPLIED);
        deployment = registry.configure(deployment.revision(), deployment.pins(), budget()).value().orElseThrow();
        observe(peer, Duration.ofSeconds(5));
        assertThatThrownBy(() -> assignments.requireAssigned(intent, peer, budget()))
                .isInstanceOf(AccessDeniedException.class);
        assertThat(assignments.assign(intent, peer, budget()).status()).isEqualTo(Status.CONFLICT);
        assertThat(writer.consumeManagement(redemption(intent, UUID.randomUUID()), actor, peer, budget())).isEmpty();
    }

    @Test
    void assignedAWithUnassignedBAndSwappedFinalSqlIdentifiersCannotConsumeB() throws Exception {
        assertThat(assignments.assign(intent, peer, budget()).status()).isEqualTo(Status.APPLIED);
        UUID b = UUID.randomUUID();
        var other = new ManagementPreparation(b, UUID.randomUUID(), actor, session, preparation.action(), model,
                preparation.payload(), 32, expiry);
        assertThat(writer.prepareManagement(other, actor, budget()).status()).isEqualTo(Status.APPLIED);
        var q = redemption(b, UUID.randomUUID());
        var tx = new org.springframework.transaction.support.TransactionTemplate(transactions);
        var changed = tx
                .execute(status -> models
                        .consumeAssignedManagementIntent(q, intent, peer.role().name(), peer.subject(),
                                Instant.now().plusSeconds(2)));
        assertThat(changed).isZero();
        assertThat(writer.consumeManagement(q, actor, peer, budget())).isEmpty();
        assertThat(writer.consumeManagement(redemption(intent, UUID.randomUUID()), actor, peer, budget())).isPresent();
    }

    @ParameterizedTest
    @ValueSource(strings = {"actor", "session", "configuration", "revision", "action", "expiry", "payload"})
    void everyStoredManagementBindingFieldAndPayloadDigestIsFinalChecked(String field) throws Exception {
        UUID correlation = consumeForOutcome();
        var original = outcome(correlation, provider("OK"));
        var json = new com.fasterxml.jackson.databind.ObjectMapper();
        var document = (com.fasterxml.jackson.databind.node.ObjectNode) json.readTree(original.requestBytes());
        var binding = (com.fasterxml.jackson.databind.node.ObjectNode) document.get("binding");
        switch (field) {
            case "actor" -> binding.put("actorId", UUID.randomUUID().toString());
            case "session" -> binding.put("sessionId", UUID.randomUUID().toString());
            case "configuration" -> binding.put("configurationId", UUID.randomUUID().toString());
            case "revision" -> binding.put("configurationRevision", model.configuration() + 1);
            case "action" -> binding.put("action", "CAPABILITY_CHECK");
            case "expiry" -> binding.put("expiresAt", expiry.plusSeconds(1).toString());
            case "payload" -> document.put("payloadSha256", "a".repeat(64));
            default -> throw new AssertionError();
        }
        var changed = wire.readOutcome(json.writeValueAsBytes(document));
        assertThat(outcomes.append(changed, peer, budget()).status()).isEqualTo(Status.DENIED);
        assertThat(count("ai_model_management_outcome")).isZero();
        assertThat(outcomes.append(original, peer, budget()).status()).isEqualTo(Status.APPLIED);
    }

    @Test
    void manuallyConstructedOutcomeFieldsNeverOverrideTheOwnedOriginalWireBytes() throws Exception {
        UUID correlation = consumeForOutcome();
        var original = outcome(correlation, provider("ORIGINAL_CANARY"));
        var supplied = new com.otilm.core.service.ai.AiRuntimeManagementWire.OutcomeRequest(1, "management-outcome",
                UUID.randomUUID(), UUID.randomUUID(), original.binding(), "a".repeat(64),
                com.otilm.core.service.ai.AiRuntimeGatewayWire.TransportCode.UNKNOWN, null, null, 0,
                com.otilm.core.service.ai.AiRuntimeGatewayWire.Usage.UNKNOWN, "b".repeat(64), original.requestBytes(),
                "FORGED_CANARY".getBytes(StandardCharsets.UTF_8));
        var result = outcomes.append(supplied, peer, budget());
        assertThat(result.status()).isEqualTo(Status.APPLIED);
        assertThat(result.value().orElseThrow().intentId()).isEqualTo(intent);
        assertThat(result.value().orElseThrow().outcomeSha256()).isEqualTo(original.outcomeSha256());
        assertThat(outcomes.read(session, intent, actor, budget()).orElseThrow().text()).isEqualTo("ORIGINAL_CANARY");
    }

    @ParameterizedTest
    @ValueSource(strings = {"unchanged", "revoke", "model", "output", "expiry"})
    void boundedValidationHoldsNoDeploymentLockAndFinalReadRejectsActualConcurrentDrift(String change)
            throws Exception {
        UUID correlation = consumeForOutcome();
        var q = outcome(correlation, provider("OK"));
        var validation = com.otilm.core.model.ai.AiModelRunResult.validate(q.responseBytes(), "lab", 32);
        var entered = new java.util.concurrent.CountDownLatch(1);
        var release = new java.util.concurrent.CountDownLatch(1);
        var executor = java.util.concurrent.Executors.newSingleThreadExecutor();
        try {
            var result = executor.submit(() -> {
                try (var mocked = org.mockito.Mockito.mockStatic(com.otilm.core.model.ai.AiModelRunResult.class)) {
                    mocked
                            .when(() -> com.otilm.core.model.ai.AiModelRunResult
                                    .validate(org.mockito.ArgumentMatchers.any(),
                                            org.mockito.ArgumentMatchers.eq("lab"),
                                            org.mockito.ArgumentMatchers.eq(32)))
                            .thenAnswer(call -> {
                                entered.countDown();
                                if (!release.await(3, java.util.concurrent.TimeUnit.SECONDS)) {
                                    throw new AssertionError("Validation release missing");
                                }
                                return validation;
                            });
                    return outcomes.append(q, peer, budget());
                }
            });
            assertThat(entered.await(2, java.util.concurrent.TimeUnit.SECONDS)).isTrue();
            assertThat(result.isDone()).isFalse();
            try (var c = source.getConnection(); var sql = c.createStatement()) {
                c.setAutoCommit(false);
                try (var rows = sql
                        .executeQuery(
                                "SELECT revision FROM ai_management_gateway_deployment WHERE id=1 FOR UPDATE NOWAIT")) {
                    assertThat(rows.next()).isTrue();
                }
                c.commit();
            }
            if (change.equals("revoke")) {
                assertThat(registry.revoke(peer, budget()).status()).isEqualTo(Status.APPLIED);
            } else if (change.equals("model")) {
                execute("UPDATE ai_model_management_intent SET model_identifier='foreign' WHERE uuid='" + intent + "'");
            } else if (change.equals("output")) {
                execute("UPDATE ai_model_management_intent SET output_tokens=31 WHERE uuid='" + intent + "'");
            } else if (change.equals("expiry")) {
                execute("UPDATE ai_model_management_intent SET expires_at=expires_at+interval '1 second' WHERE uuid='"
                        + intent + "'");
            }
            release.countDown();
            assertThat(result.get(3, java.util.concurrent.TimeUnit.SECONDS).status())
                    .isEqualTo(change.equals("unchanged") ? Status.APPLIED : Status.DENIED);
            assertThat(count("ai_model_management_outcome")).isEqualTo(change.equals("unchanged") ? 1 : 0);
            assertThat(AiModelDispatchFixture.reservedTokens(source, session, true)).isEqualTo(32);
        } finally {
            release.countDown();
            executor.shutdownNow();
            assertThat(executor.awaitTermination(3, java.util.concurrent.TimeUnit.SECONDS)).isTrue();
        }
    }

    @ParameterizedTest
    @ValueSource(strings = {"assign-same", "assign-foreign", "append-same", "append-conflict"})
    void twoActualPostgresqlReplicasSerializeAtTheOwnedDeploymentLockWithoutOverwrite(String operation)
            throws Exception {
        boolean append = operation.startsWith("append");
        var other = operation.equals("assign-foreign") ? otherPeer() : peer;
        if (other != peer) {
            observe(other, Duration.ofSeconds(5));
        }
        UUID correlation = append ? consumeForOutcome() : UUID.randomUUID();
        var q = outcome(correlation, provider("OK"));
        var otherOutcome = operation.equals("append-conflict") ? outcome(correlation, provider("OTHER")) : q;
        var one = new java.util.concurrent.atomic.AtomicInteger();
        var two = new java.util.concurrent.atomic.AtomicInteger();
        var executor = java.util.concurrent.Executors.newFixedThreadPool(2);
        try (var holder = source.getConnection(); var observer = source.getConnection()) {
            holder.setAutoCommit(false);
            int holderPid;
            try (var sql = holder.createStatement(); var rows = sql.executeQuery("SELECT pg_backend_pid()")) {
                rows.next();
                holderPid = rows.getInt(1);
            }
            try (var sql = holder.createStatement();
                    var rows = sql
                            .executeQuery(
                                    "SELECT revision FROM ai_management_gateway_deployment WHERE id=1 FOR UPDATE")) {
                assertThat(rows.next()).isTrue();
            }
            var first = executor
                    .submit(() -> replica(one,
                            remaining -> append
                                    ? outcomes.append(q, peer, remaining).status()
                                    : assignments.assign(intent, peer, remaining).status()));
            var second = executor
                    .submit(() -> replica(two,
                            remaining -> append
                                    ? outcomes.append(otherOutcome, peer, remaining).status()
                                    : assignments.assign(intent, other, remaining).status()));
            org.awaitility.Awaitility
                    .await("Both exact owned backend waiters")
                    .pollInSameThread()
                    .pollDelay(Duration.ZERO)
                    .pollInterval(Duration.ofMillis(2))
                    .atMost(Duration.ofMillis(500))
                    .until(() -> {
                        if (one.get() <= 0 || two.get() <= 0 || one.get() == two.get() || one.get() == holderPid
                                || two.get() == holderPid) {
                            return false;
                        }
                        var graph = blockingGraph(observer, holderPid, one.get(), two.get());
                        return graph.keySet().containsAll(java.util.Set.of(holderPid, one.get(), two.get()))
                                && pathToHolder(graph, holderPid, one.get(), two.get())
                                && pathToHolder(graph, holderPid, two.get(), one.get()) && !first.isDone()
                                && !second.isDone();
                    });
            holder.commit();
            var a = first.get(3, java.util.concurrent.TimeUnit.SECONDS);
            var b = second.get(3, java.util.concurrent.TimeUnit.SECONDS);
            assertThat(java.util.List.of(a, b))
                    .containsExactlyInAnyOrder(Status.APPLIED,
                            operation.endsWith("same") ? Status.REPLAY : Status.CONFLICT);
            assertThat(count(append ? "ai_model_management_outcome" : "ai_model_management_gateway_assignment"))
                    .isEqualTo(1);
        } finally {
            executor.shutdownNow();
            assertThat(executor.awaitTermination(3, java.util.concurrent.TimeUnit.SECONDS)).isTrue();
        }
    }

    @Test
    void heldDeploymentRowUsesRemainingDatabaseBudgetAndRollsBackWithoutChangingAnyFact() throws Exception {
        var pid = new java.util.concurrent.atomic.AtomicInteger();
        var elapsed = new java.util.concurrent.atomic.AtomicLong();
        var executor = java.util.concurrent.Executors.newSingleThreadExecutor();
        String before = AiModelDispatchFixture.fingerprint(source);
        try (var holder = source.getConnection(); var observer = source.getConnection()) {
            holder.setAutoCommit(false);
            int holderPid;
            try (var sql = holder.createStatement(); var rows = sql.executeQuery("SELECT pg_backend_pid()")) {
                rows.next();
                holderPid = rows.getInt(1);
            }
            try (var sql = holder.createStatement();
                    var rows = sql
                            .executeQuery(
                                    "SELECT revision FROM ai_management_gateway_deployment WHERE id=1 FOR UPDATE")) {
                assertThat(rows.next()).isTrue();
            }
            var result = executor.submit(() -> {
                var remaining = AiRuntimeOperationBudget.start(Duration.ofMillis(800));
                return withBudget(remaining, () -> {
                    var tx = new org.springframework.transaction.support.TransactionTemplate(transactions);
                    tx.setTimeout(5);
                    try {
                        return tx.execute(status -> {
                            pid
                                    .set(((Number) entityManager
                                            .createNativeQuery("SELECT pg_backend_pid()")
                                            .getSingleResult()).intValue());
                            long start = System.nanoTime();
                            try {
                                registry.configure(deployment.revision(), deployment.pins(), remaining);
                                return "NO_FAILURE";
                            } finally {
                                elapsed.set(System.nanoTime() - start);
                            }
                        });
                    } catch (RuntimeException failure) {
                        for (Throwable cause = failure; cause != null; cause = cause.getCause()) {
                            if (cause instanceof java.sql.SQLException sql) {
                                return sql.getSQLState();
                            }
                        }
                        throw failure;
                    }
                });
            });
            org.awaitility.Awaitility
                    .await("Exact owned budget waiter")
                    .pollInSameThread()
                    .pollDelay(Duration.ZERO)
                    .pollInterval(Duration.ofMillis(2))
                    .atMost(Duration.ofMillis(200))
                    .until(() -> {
                        if (pid.get() <= 0 || pid.get() == holderPid) {
                            return false;
                        }
                        var graph = blockingGraph(observer, holderPid, pid.get(), pid.get());
                        return graph.getOrDefault(pid.get(), java.util.List.of()).contains(holderPid)
                                && !result.isDone();
                    });
            assertThat(result.get(2, java.util.concurrent.TimeUnit.SECONDS)).isIn("55P03", "57014");
            assertThat(elapsed.get())
                    .as("Actual lock timeout must fit the remaining 800ms rather than old fixed1000ms")
                    .isLessThan(Duration.ofMillis(850).toNanos());
            holder.rollback();
            assertThat(registry.revision(budget())).isEqualTo(deployment.revision());
            assertThat(AiModelDispatchFixture.fingerprint(source)).isEqualTo(before);
        } finally {
            executor.shutdownNow();
            assertThat(executor.awaitTermination(3, java.util.concurrent.TimeUnit.SECONDS)).isTrue();
        }
    }

    private Status replica(java.util.concurrent.atomic.AtomicInteger pid,
            Function<AiRuntimeOperationBudget, Status> call) {
        var remaining = budget();
        return withBudget(remaining, () -> {
            var tx = new org.springframework.transaction.support.TransactionTemplate(transactions);
            tx.setTimeout(5);
            return tx.execute(status -> {
                pid
                        .set(((Number) entityManager.createNativeQuery("SELECT pg_backend_pid()").getSingleResult())
                                .intValue());
                return call.apply(remaining);
            });
        });
    }

    @SuppressWarnings("unchecked")
    private <T> T withBudget(AiRuntimeOperationBudget remaining, Supplier<T> work) {
        var callback = (ProceedingJoinPoint) Proxy
                .newProxyInstance(ProceedingJoinPoint.class.getClassLoader(), new Class<?>[]{ProceedingJoinPoint.class},
                        (proxy, method, arguments) -> {
                            if (method.getName().equals("proceed")) {
                                return work.get();
                            }
                            throw new UnsupportedOperationException(method.getName());
                        });
        try {
            return (T) jdbcBudget.invoke(callback, remaining);
        } catch (RuntimeException | Error failure) {
            throw failure;
        } catch (Throwable failure) {
            throw new IllegalStateException("Test budget callback failed", failure);
        }
    }

    private static boolean pathToHolder(java.util.Map<Integer, java.util.List<Integer>> graph, int holder, int writer,
            int other) {
        var blockers = graph.getOrDefault(writer, java.util.List.of());
        return !blockers.isEmpty() && java.util.Set.of(holder, other).containsAll(blockers)
                && (blockers.contains(holder)
                        || blockers.contains(other) && graph.getOrDefault(other, java.util.List.of()).contains(holder));
    }

    private static java.util.Map<Integer, java.util.List<Integer>> blockingGraph(java.sql.Connection observer,
            int holder, int first, int second) throws Exception {
        try (var q = observer
                .prepareStatement("SELECT pid,pg_blocking_pids(pid) FROM pg_stat_activity WHERE pid IN (?,?,?)")) {
            q.setInt(1, holder);
            q.setInt(2, first);
            q.setInt(3, second);
            try (var rows = q.executeQuery()) {
                var graph = new java.util.HashMap<Integer, java.util.List<Integer>>();
                while (rows.next()) {
                    graph.put(rows.getInt(1), java.util.List.of((Integer[]) rows.getArray(2).getArray()));
                }
                return java.util.Map.copyOf(graph);
            }
        }
    }

    @Test
    void anUnknownIntentCannotBecomeADelegationForEvenACurrentNativeMember() throws Exception {
        UUID unknown = UUID.randomUUID();
        assertThat(assignments.assign(unknown, peer, budget()).status()).isEqualTo(Status.DENIED);
        assertThatThrownBy(() -> assignments.requireAssigned(unknown, peer, budget()))
                .isInstanceOf(AccessDeniedException.class);
        assertThat(count("ai_model_management_gateway_assignment")).isZero();
        assertThat(assignments.assign(intent, peer, budget()).status()).isEqualTo(Status.APPLIED);
    }

    @Test
    void realStoredProjectionAndSuspendedCallerTransactionComposeThroughFreshConnect() throws Exception {
        var auth = org.mockito.Mockito.mock(com.otilm.core.security.ai.AiModelManagementAuthorization.class);
        org.mockito.Mockito.doAnswer(call -> {
            assertThat(org.springframework.transaction.support.TransactionSynchronizationManager
                    .isActualTransactionActive()).isFalse();
            return null;
        })
                .when(auth)
                .requireConnect(org.mockito.ArgumentMatchers.eq(actor), org.mockito.ArgumentMatchers.eq(model.id()),
                        org.mockito.ArgumentMatchers.any());
        var factory = new org.springframework.aop.framework.ProxyFactory(
                new com.otilm.core.service.ai.AiModelManagementDispatchService(sessions, writer, auth,
                        new AiFeatureGate(true)));
        factory.setProxyTargetClass(true);
        factory
                .addAdvice(new org.springframework.transaction.interceptor.TransactionInterceptor(
                        (org.springframework.transaction.TransactionManager) transactions,
                        new org.springframework.transaction.annotation.AnnotationTransactionAttributeSource()));
        var service = (com.otilm.core.service.ai.AiModelManagementDispatchService) factory.getProxy();
        UUID key = UUID.randomUUID();
        var outer = new org.springframework.transaction.support.TransactionTemplate(transactions);
        var prepared = outer.execute(status -> {
            assertThat(org.springframework.transaction.support.TransactionSynchronizationManager
                    .isActualTransactionActive()).isTrue();
            var result = service.prepare(session, key, budget());
            assertThat(org.springframework.transaction.support.TransactionSynchronizationManager
                    .isActualTransactionActive()).isTrue();
            return result;
        });
        assertThat(prepared.status()).isEqualTo(Status.APPLIED);
        var envelope = prepared.value().orElseThrow();
        var stored = models.preparedManagementByKey(session, key).orElseThrow();
        assertThat(stored).isEqualTo(models.preparedManagementById(session, envelope.intentId()).orElseThrow());
        assertThat(stored.actorId()).isEqualTo(actor);
        assertThat(stored.sessionId()).isEqualTo(session);
        assertThat(stored.connection()).isEqualTo(model);
        assertThat(stored.expiresAt()).isEqualTo(expiry);
        assertThat(stored.action()).isEqualTo(preparation.action());
        assertThat(stored.outputTokens()).isEqualTo(32);
        assertThat(stored.payload().sha256()).isEqualTo(envelope.payloadSha256());
        assertThat(models.preparedManagementById(UUID.randomUUID(), envelope.intentId())).isEmpty();
        assertThat(models.preparedManagementByKey(UUID.randomUUID(), key)).isEmpty();
        assertThat(assignments.assign(envelope.intentId(), peer, budget()).status()).isEqualTo(Status.APPLIED);
        UUID correlation = UUID.randomUUID();
        var consumed = outer.execute(status -> service.consume(envelope, correlation, peer, budget()));
        assertThat(consumed).isPresent();
        // The concrete CONNECT boundary is synthetic here; SQL and transaction suspension are real.
        org.mockito.Mockito
                .verify(auth, org.mockito.Mockito.times(2))
                .requireConnect(org.mockito.ArgumentMatchers.eq(actor), org.mockito.ArgumentMatchers.eq(model.id()),
                        org.mockito.ArgumentMatchers.any());
        assertThat(count("ai_runtime_run")).isZero();
    }

    private void observe(RuntimePeer value, Duration window) throws Exception {
        Instant now = AiRuntimeFixture.now(source);
        assertThat(registry
                .observe(new Observation(deployment, value.subject(), 1, UUID.randomUUID(), now, now.plus(window)),
                        budget())
                .status()).isEqualTo(Status.APPLIED);
    }

    private RuntimePeer otherPeer() {
        return new RuntimePeer(RuntimePeerRole.GATEWAY_MANAGEMENT,
                new RuntimeProxyCertificateClaims(peer.subject().cluster(), peer.subject().namespace(),
                        peer.subject().serviceAccount(), "other-gateway", UUID.randomUUID()));
    }

    private ManagementRedemption redemption(UUID id, UUID correlation) {
        return new ManagementRedemption(id, actor, session, preparation.action(), model, preparation.payload().sha256(),
                expiry, correlation);
    }

    private void execute(String sql) throws Exception {
        try (var c = source.getConnection(); var s = c.createStatement()) {
            s.execute(sql);
        }
    }

    private long count(String table) throws Exception {
        if (!java.util.Set
                .of("ai_runtime_control", "ai_runtime_run", "ai_model_management_outcome",
                        "ai_model_management_gateway_assignment")
                .contains(table)) {
            throw new AssertionError();
        }
        try (var c = source.getConnection();
                var s = c.createStatement();
                var rows = s.executeQuery("SELECT count(*) FROM " + table)) {
            rows.next();
            return rows.getLong(1);
        }
    }

    private static AiRuntimeOperationBudget budget() {
        return AiRuntimeOperationBudget.start();
    }
}
