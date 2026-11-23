package com.otilm.core.integration.service;

import com.otilm.core.dao.repository.ai.AiModelDispatchRepository;
import com.otilm.core.dao.repository.ai.AiModelRunInputRepository;
import com.otilm.core.dao.repository.ai.AiRuntimeRepository;
import com.otilm.core.model.ai.AiModelDispatchState.ConnectionVersion;
import com.otilm.core.model.ai.AiModelRunInput;
import com.otilm.core.model.ai.AiRuntimeState.RunSnapshot;
import com.otilm.core.model.ai.AiRuntimeState.Status;
import com.otilm.core.service.ai.AiRuntimeKernel;
import com.otilm.core.service.writer.ai.AiModelRunInputWriter;
import com.otilm.core.util.AiModelDispatchFixture;
import com.otilm.core.util.AiRuntimeFixture;
import com.otilm.core.util.ai.BaseAiSpringBootTest;
import java.sql.Connection;
import java.sql.SQLException;
import java.time.Duration;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import javax.sql.DataSource;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.aop.framework.ProxyFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.annotation.AnnotationTransactionAttributeSource;
import org.springframework.transaction.interceptor.TransactionInterceptor;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.catchThrowable;
import static org.awaitility.Awaitility.await;

/** Real owned PostgreSQL storage proof; no modelUSE or native caller authority is supplied by this fixture. */
class AiModelRunInputITest extends BaseAiSpringBootTest {
    @Autowired
    private DataSource source;
    @Autowired
    private AiRuntimeKernel kernel;
    @Autowired
    private AiModelRunInputWriter writer;
    @Autowired
    private AiRuntimeRepository runtime;
    @Autowired
    private AiModelDispatchRepository models;
    @Autowired
    private AiModelRunInputRepository inputs;
    @Autowired
    private PlatformTransactionManager transactions;
    private ConnectionVersion model;
    private RunSnapshot run;

    @BeforeEach
    void installRealSchemaAndOwnedRun() throws Exception {
        AiModelDispatchFixture.drop(source);
        AiRuntimeFixture.install(source);
        model = AiModelDispatchFixture.approvedModel(source);
        var now = AiRuntimeFixture.now(source);
        var control = AiRuntimeFixture.enableTestControl(kernel, now);
        run = kernel.create(control, AiRuntimeFixture.run(now), AiRuntimeFixture.attempt(now));
        AiModelDispatchFixture.runBudget(source, run.spec().runId(), model, 3, 128);
    }

    @Test
    void metadataExistsBeforeProtectedInputAndRoundTripOwnsTheScope() throws Exception {
        assertThat(writer.connection(run.spec().runId())).contains(model);
        assertThat(writer.read(run.spec().runId(), model)).isEmpty();
        UUID certificate = UUID.randomUUID();
        Set<UUID> scope = new HashSet<>(Set.of(certificate));
        var input = new AiModelRunInput(run.spec().runId(), UUID.randomUUID(), scope, "instruction 🧪", "prompt\ntext",
                32);
        scope.clear();
        assertThat(writer.store(input).status()).isEqualTo(Status.APPLIED);
        assertThat(writer.read(input.runId(), model)).contains(input);
        assertThat(writer.connection(input.runId())).contains(model);
        assertThat(count()).isEqualTo(1);
    }

    @Test
    void realArrayBindingPreservesEmptyAndHundredCertificateScopes() throws Exception {
        var empty = new AiModelRunInput(run.spec().runId(), UUID.randomUUID(), Set.of(), "instructions", "prompt", 32);
        assertThat(writer.store(empty).status()).isEqualTo(Status.APPLIED);
        assertThat(writer.read(empty.runId(), model)).contains(empty);
        var now = AiRuntimeFixture.now(source);
        var second = kernel
                .create(kernel.control().orElseThrow().version(), AiRuntimeFixture.run(now),
                        AiRuntimeFixture.attempt(now));
        AiModelDispatchFixture.runBudget(source, second.spec().runId(), model, 3, 128);
        Set<UUID> hundred = new HashSet<>();
        for (int index = 0; index < 100; index++) {
            hundred.add(new UUID(0, index));
        }
        var bounded = new AiModelRunInput(second.spec().runId(), UUID.randomUUID(), hundred, "instructions", "prompt",
                32);
        assertThat(writer.store(bounded).status()).isEqualTo(Status.APPLIED);
        assertThat(writer.read(bounded.runId(), model)).contains(bounded);
        assertThat(writer.store(bounded).status()).isEqualTo(Status.REPLAY);
    }

    @Test
    void exactReplayAndEveryChangedFieldKeepTheOriginalRow() throws Exception {
        var original = input(run.spec().runId(), "original");
        assertThat(writer.store(original).status()).isEqualTo(Status.APPLIED);
        assertThat(writer.store(original).status()).isEqualTo(Status.REPLAY);
        List<AiModelRunInput> altered = List
                .of(new AiModelRunInput(original.runId(), UUID.randomUUID(), original.certificateUuids(),
                        original.instructions(), original.prompt(), original.outputTokens()),
                        new AiModelRunInput(original.runId(), original.raProfileUuid(), Set.of(UUID.randomUUID()),
                                original.instructions(), original.prompt(), original.outputTokens()),
                        new AiModelRunInput(original.runId(), original.raProfileUuid(), original.certificateUuids(),
                                "changed", original.prompt(), original.outputTokens()),
                        new AiModelRunInput(original.runId(), original.raProfileUuid(), original.certificateUuids(),
                                original.instructions(), "changed", original.outputTokens()),
                        new AiModelRunInput(original.runId(), original.raProfileUuid(), original.certificateUuids(),
                                original.instructions(), original.prompt(), 64));
        for (var changed : altered) {
            assertThat(writer.store(changed).status()).isEqualTo(Status.CONFLICT);
            assertThat(writer.read(original.runId(), model)).contains(original);
        }
        assertThat(count()).isEqualTo(1);
    }

    @Test
    void missingRunBudgetOrInputNeverFallsBackToAnotherExecution() throws Exception {
        UUID absent = UUID.randomUUID();
        assertThat(writer.store(input(absent, "absent")).status()).isEqualTo(Status.DENIED);
        assertThat(writer.connection(absent)).isEmpty();
        assertThat(writer.read(absent, model)).isEmpty();
        execute("DELETE FROM ai_model_run_budget WHERE run_uuid = ?", run.spec().runId());
        assertThat(writer.store(input(run.spec().runId(), "no-budget")).status()).isEqualTo(Status.DENIED);
        assertThat(count()).isZero();
    }

    @Test
    void protectedReadRequiresExactBoundModelAndVersions() throws Exception {
        var original = input(run.spec().runId(), "original");
        assertThat(writer.store(original).status()).isEqualTo(Status.APPLIED);
        ConnectionVersion foreign = AiModelDispatchFixture.approvedModel(source);
        assertThat(writer.read(original.runId(), foreign)).isEmpty();
        var changed = new ConnectionVersion(model.id(), model.configuration() + 1, model.destination(),
                model.authentication(), model.modelIdentifier());
        assertThat(writer.read(original.runId(), changed)).isEmpty();
        AiModelDispatchFixture.reviseConnection(source, model.id());
        assertThat(writer.connection(original.runId())).isEmpty();
        assertThat(writer.read(original.runId(), model)).isEmpty();
    }

    @Test
    void twoRunsCannotAliasEachOthersInput() throws Exception {
        var secondRun = kernel
                .create(kernel.control().orElseThrow().version(), AiRuntimeFixture.run(AiRuntimeFixture.now(source)),
                        AiRuntimeFixture.attempt(AiRuntimeFixture.now(source)));
        ConnectionVersion secondModel = AiModelDispatchFixture.approvedModel(source);
        AiModelDispatchFixture.runBudget(source, secondRun.spec().runId(), secondModel, 3, 128);
        var first = input(run.spec().runId(), "first");
        var second = input(secondRun.spec().runId(), "second");
        assertThat(writer.store(first).status()).isEqualTo(Status.APPLIED);
        assertThat(writer.store(second).status()).isEqualTo(Status.APPLIED);
        assertThat(writer.read(first.runId(), secondModel)).isEmpty();
        assertThat(writer.read(second.runId(), model)).isEmpty();
        assertThat(writer.read(first.runId(), model)).contains(first);
        assertThat(writer.read(second.runId(), secondModel)).contains(second);
    }

    @Test
    void databaseRejectsUpdateAndDeleteBeforeAnyReplacement() throws Exception {
        var original = input(run.spec().runId(), "SQL_CANARY");
        seed(original);
        assertSqlState("UPDATE ai_model_run_input SET prompt = 'changed' WHERE run_uuid = ?", original.runId(),
                "55000");
        assertSqlState("DELETE FROM ai_model_run_input WHERE run_uuid = ?", original.runId(), "55000");
        assertThat(writer.read(original.runId(), model)).contains(original);
        assertThat(writer.store(input(original.runId(), "replacement")).status()).isEqualTo(Status.CONFLICT);
    }

    @Test
    void cancelledRunStillCannotDeleteAndReplaceItsRetainedInput() throws Exception {
        var original = input(run.spec().runId(), "retained");
        seed(original);
        assertThat(kernel.cancel(original.runId()).status()).isEqualTo(Status.APPLIED);
        assertSqlState("DELETE FROM ai_model_run_input WHERE run_uuid = ?", original.runId(), "55000");
        assertThat(count()).isEqualTo(1);
    }

    @Test
    void parentRetentionDeleteMayCascadeWithoutLeavingOrphanedInput() throws Exception {
        var original = input(run.spec().runId(), "retained");
        seed(original);
        try (var connection = source.getConnection()) {
            connection.setAutoCommit(false);
            for (String sql : List
                    .of("DELETE FROM ai_model_run_budget WHERE run_uuid = ?",
                            "DELETE FROM ai_runtime_workload WHERE attempt_uuid IN (SELECT uuid FROM ai_runtime_attempt WHERE run_uuid = ?)",
                            "DELETE FROM ai_runtime_launch WHERE attempt_uuid IN (SELECT uuid FROM ai_runtime_attempt WHERE run_uuid = ?)",
                            "DELETE FROM ai_runtime_attempt WHERE run_uuid = ?",
                            "DELETE FROM ai_runtime_run WHERE uuid = ?")) {
                try (var statement = connection.prepareStatement(sql)) {
                    statement.setObject(1, original.runId());
                    statement.executeUpdate();
                }
            }
            connection.commit();
        }
        assertThat(count()).isZero();
    }

    @Test
    void callerSearchPathCannotPretendTheParentWasRemoved() throws Exception {
        var original = input(run.spec().runId(), "search-path-canary");
        seed(original);
        try (var connection = source.getConnection(); var statement = connection.createStatement()) {
            String schema = connection.getSchema();
            assertThat(schema).matches("[a-z_][a-z0-9_]*");
            statement.execute("CREATE TEMP TABLE ai_runtime_run(uuid UUID)");
            try {
                statement.execute("SET search_path TO pg_temp, " + schema);
                String sql = "DELETE FROM " + schema + ".ai_model_run_input WHERE run_uuid = ?";
                Throwable failure = catchThrowable(() -> execute(connection, sql, original.runId()));
                assertThat(failure).isInstanceOf(org.postgresql.util.PSQLException.class);
                assertThat(((SQLException) failure).getSQLState()).isEqualTo("55000");
            } finally {
                statement.execute("RESET search_path");
                statement.execute("DROP TABLE IF EXISTS pg_temp.ai_runtime_run");
            }
        }
        assertThat(count()).isEqualTo(1);
    }

    @Test
    void independentWritersWaitForTheRealRunLockThenOneImmutableValueWins() throws Exception {
        var first = input(run.spec().runId(), "first");
        var second = input(run.spec().runId(), "second");
        var factory = new ProxyFactory(new AiModelRunInputWriter(runtime, models, inputs));
        factory.addAdvice(new TransactionInterceptor(transactions, new AnnotationTransactionAttributeSource()));
        var replica = (AiModelRunInputWriter) factory.getProxy();
        var started = new CountDownLatch(2);
        try (var lock = source.getConnection(); var workers = Executors.newFixedThreadPool(2)) {
            lock.setAutoCommit(false);
            execute(lock, "SELECT uuid FROM ai_runtime_run WHERE uuid = ? FOR UPDATE", first.runId());
            var a = workers.submit(() -> {
                started.countDown();
                return writer.store(first).status();
            });
            var b = workers.submit(() -> {
                started.countDown();
                return replica.store(second).status();
            });
            assertThat(started.await(2, TimeUnit.SECONDS)).isTrue();
            await().atMost(Duration.ofSeconds(3)).untilAsserted(() -> assertThat(runLockWaiters()).isEqualTo(2));
            lock.commit();
            assertThat(List.of(a.get(10, TimeUnit.SECONDS), b.get(10, TimeUnit.SECONDS)))
                    .containsExactlyInAnyOrder(Status.APPLIED, Status.CONFLICT);
        }
        assertThat(count()).isEqualTo(1);
        assertThat(writer.read(first.runId(), model).orElseThrow()).isIn(first, second);
    }

    @Test
    void unversionedActorChangeCannotReadOrReplayThePreviousOwnersInput() throws Exception {
        var original = input(run.spec().runId(), "owner-private-canary");
        assertThat(writer.store(original).status()).isEqualTo(Status.APPLIED);
        assertThat(writer.read(original.runId(), model)).contains(original);
        execute("UPDATE ai_runtime_run SET actor_uuid = ? WHERE uuid = ?", UUID.randomUUID(), original.runId());
        assertThat(writer.connection(original.runId())).contains(model);
        assertThat(writer.read(original.runId(), model)).isEmpty();
        assertThat(writer.store(original).status()).isEqualTo(Status.CONFLICT);
        assertThat(count()).isEqualTo(1);
    }

    @Test
    void truncateCannotEraseAndReplaceAnActiveExecutionInput() throws Exception {
        var original = input(run.spec().runId(), "truncate-private-canary");
        assertThat(writer.store(original).status()).isEqualTo(Status.APPLIED);
        Throwable failure = catchThrowable(() -> execute("TRUNCATE ai_model_run_input"));
        assertThat(failure).isInstanceOf(org.postgresql.util.PSQLException.class);
        var rejected = (org.postgresql.util.PSQLException) failure;
        assertThat(rejected.getSQLState()).isEqualTo("55000");
        assertThat(rejected.getServerErrorMessage().getMessage()).isEqualTo("Stored model run input is immutable");
        assertThat(writer.read(original.runId(), model)).contains(original);
        assertThat(writer.store(input(original.runId(), "replacement")).status()).isEqualTo(Status.CONFLICT);
        assertThat(count()).isEqualTo(1);
    }

    private static AiModelRunInput input(UUID run, String text) {
        return new AiModelRunInput(run, UUID.randomUUID(), Set.of(UUID.randomUUID()), "instruction-" + text,
                "prompt-" + text, 32);
    }

    private void seed(AiModelRunInput input) throws Exception {
        try (var connection = source.getConnection();
                var statement = connection
                        .prepareStatement(
                                "INSERT INTO ai_model_run_input(run_uuid, actor_uuid, ra_profile_uuid, certificate_uuids, instructions, prompt, output_tokens) SELECT uuid, actor_uuid, ?, ?, ?, ?, ? FROM ai_runtime_run WHERE uuid = ?")) {
            statement.setObject(1, input.raProfileUuid());
            statement.setArray(2, connection.createArrayOf("uuid", input.certificateUuids().toArray()));
            statement.setString(3, input.instructions());
            statement.setString(4, input.prompt());
            statement.setInt(5, input.outputTokens());
            statement.setObject(6, input.runId());
            assertThat(statement.executeUpdate()).isEqualTo(1);
        }
    }

    private void assertSqlState(String sql, UUID runId, String state) {
        Throwable failure = catchThrowable(() -> execute(sql, runId));
        assertThat(failure).isInstanceOf(org.postgresql.util.PSQLException.class);
        assertThat(((SQLException) failure).getSQLState()).isEqualTo(state);
    }

    private int runLockWaiters() throws Exception {
        try (var connection = source.getConnection();
                var statement = connection.createStatement();
                var rows = statement
                        .executeQuery(
                                "SELECT count(*) FROM pg_stat_activity WHERE datname = current_database() AND wait_event_type = 'Lock' AND query ILIKE '%ai_runtime_run%' AND query ILIKE '%FOR UPDATE%'")) {
            rows.next();
            return rows.getInt(1);
        }
    }

    private int count() throws Exception {
        try (var connection = source.getConnection();
                var statement = connection.createStatement();
                var rows = statement.executeQuery("SELECT count(*) FROM ai_model_run_input")) {
            rows.next();
            return rows.getInt(1);
        }
    }

    private void execute(String sql, Object... values) throws Exception {
        try (var connection = source.getConnection()) {
            execute(connection, sql, values);
        }
    }

    private static void execute(Connection connection, String sql, Object... values) throws Exception {
        try (var statement = connection.prepareStatement(sql)) {
            for (int index = 0; index < values.length; index++) {
                statement.setObject(index + 1, values[index]);
            }
            statement.execute();
        }
    }
}
