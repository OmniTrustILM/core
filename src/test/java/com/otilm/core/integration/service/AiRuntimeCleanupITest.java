package com.otilm.core.integration.service;

import com.otilm.core.dao.repository.ai.AiRuntimeRepository;
import com.otilm.core.model.ai.AiRuntimeState.AttemptSpec;
import com.otilm.core.model.ai.AiRuntimeState.CleanupState;
import com.otilm.core.model.ai.AiRuntimeState.Expected;
import com.otilm.core.model.ai.AiRuntimeState.RunSnapshot;
import com.otilm.core.model.ai.AiRuntimeState.Status;
import com.otilm.core.model.ai.AiRuntimeState.Transition;
import com.otilm.core.model.ai.AiRuntimeState.WorkloadRef;
import com.otilm.core.model.ai.AiRuntimeState.WorkloadState;
import com.otilm.core.service.ai.AiRuntimeKernel;
import com.otilm.core.service.ai.AiRuntimeOperationBudget;
import com.otilm.core.service.writer.ai.AiRuntimeCleanupWriter;
import com.otilm.core.util.AiRuntimeFixture;
import com.otilm.core.util.ai.BaseAiSpringBootTest;
import java.sql.PreparedStatement;
import java.time.Duration;
import java.util.HashSet;
import java.util.Set;
import java.util.UUID;
import javax.sql.DataSource;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.springframework.beans.factory.annotation.Autowired;

import static com.otilm.core.util.AiRuntimeFixture.expected;
import static com.otilm.core.util.AiRuntimeFixture.observation;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/** Real PostgreSQL storage handoff only. Constructed refs are not real terminal/absence proof. */
class AiRuntimeCleanupITest extends BaseAiSpringBootTest {
    private static final WorkloadRef FIRST = new WorkloadRef("cluster-one", "pod-one");
    private static final WorkloadRef SECOND = new WorkloadRef("cluster-one", "pod-two");
    private static final Set<WorkloadRef> ALL = Set.of(FIRST, SECOND);
    private static final String JOB = "job-one";
    @Autowired
    private DataSource source;
    @Autowired
    private AiRuntimeKernel kernel;
    @Autowired
    private AiRuntimeRepository runtime;
    @Autowired
    private AiRuntimeCleanupWriter cleanup;
    @Autowired
    private com.otilm.core.dao.repository.ai.AiRuntimeCleanupRepository repository;
    @Autowired
    private jakarta.persistence.EntityManager entityManager;
    @Autowired
    private org.springframework.transaction.PlatformTransactionManager transactions;
    private UUID runId;

    @BeforeEach
    void createRecordedFootprint() throws Exception {
        AiRuntimeFixture.install(source);
        var now = AiRuntimeFixture.now(source);
        var control = AiRuntimeFixture.enableTestControl(kernel, now);
        var created = kernel.create(control, AiRuntimeFixture.run(now), AiRuntimeFixture.attempt(now));
        runId = created.spec().runId();
        assertThat(kernel.observe(observation(current(), FIRST, 1, true)).status()).isEqualTo(Status.APPLIED);
        assertThat(kernel.observe(observation(current(), SECOND, 2, true)).status()).isEqualTo(Status.APPLIED);
    }

    @Test
    void completesFootprint_whenCurrentBindingIsExact() {
        // given
        assertThat(kernel.bootstrap(expected(current()), FIRST).status()).isEqualTo(Status.APPLIED);
        var before = fence();
        assertThat(before.fence()).isNotEqualTo(before.attempt().fence());
        assertThat(runtime.outstandingWorkloads(runId)).isEqualTo(2);

        // when
        Transition<Void> result = cleanup.complete(expected(before), JOB, ALL, budget());

        // then
        assertThat(result.status()).isEqualTo(Status.APPLIED);
        RunSnapshot after = current();
        assertThat(after.spec()).isEqualTo(before.spec());
        assertThat(after.state()).isEqualTo(before.state());
        assertThat(after.revision()).isEqualTo(before.revision());
        assertThat(after.fence()).isEqualTo(before.fence());
        assertThat(after.attemptsUsed()).isEqualTo(before.attemptsUsed());
        assertThat(after.attempt()).isEqualTo(before.attempt());
        assertThat(after.createdAt()).isEqualTo(before.createdAt());
        assertThat(after.updatedAt()).isEqualTo(before.updatedAt());
        assertThat(after.launch().cleanup()).isEqualTo(CleanupState.DONE);
        assertThat(after.launch().jobUid()).isEqualTo(before.launch().jobUid());
        assertThat(after.launch().observationSequence()).isEqualTo(before.launch().observationSequence());
        assertThat(after.launch().spec()).isEqualTo(before.launch().spec());
        assertThat(after.launch().updatedAt()).isAfterOrEqualTo(before.launch().updatedAt());
        assertThat(after.workloads()).hasSize(2).allSatisfy(row -> {
            assertThat(row.state()).isEqualTo(WorkloadState.CLOSED);
            var original = before.workloads().stream().filter(x -> x.ref().equals(row.ref())).findFirst().orElseThrow();
            assertThat(row).usingRecursiveComparison().ignoringFields("updatedAt").isEqualTo(original);
            assertThat(row.updatedAt()).isAfterOrEqualTo(original.updatedAt());
        });
        assertThat(runtime.outstandingWorkloads(runId)).isZero();
    }

    @Test
    void replaysWithoutMutation_whenExactFootprintIsAlreadyDone() throws Exception {
        // given
        var fenced = fence();
        assertThat(cleanup.complete(expected(fenced), JOB, ALL, budget()).status()).isEqualTo(Status.APPLIED);
        String before = fingerprint();

        // when
        Transition<Void> result = cleanup.complete(expected(fenced), JOB, ALL, budget());

        // then
        assertThat(result.status()).isEqualTo(Status.REPLAY);
        assertThat(fingerprint()).isEqualTo(before);
    }

    @Test
    void completesEmptyFootprint_whenExactJobHasNoRecordedPods() throws Exception {
        // given
        execute("DELETE FROM ai_runtime_workload");
        var fenced = fence();
        assertThat(fenced.launch().jobUid()).contains(JOB);

        // when
        Transition<Void> result = cleanup.complete(expected(fenced), JOB, Set.of(), budget());

        // then
        assertThat(result.status()).isEqualTo(Status.APPLIED);
        assertThat(current().launch().cleanup()).isEqualTo(CleanupState.DONE);
        assertThat(cleanup.complete(expected(fenced), JOB, Set.of(), budget()).status()).isEqualTo(Status.REPLAY);
    }

    @ParameterizedTest
    @ValueSource(strings = {
            "revision",
            "fence",
            "attempt",
            "run",
            "job",
            "missing-pod",
            "extra-pod",
            "cluster",
            "foreign-job"})
    void deniesWithoutMutation_whenStoredBindingDiffers(String changed) throws Exception {
        // given
        var fenced = fence();
        var e = expected(fenced);
        if (changed.equals("foreign-job")) {
            execute("UPDATE ai_runtime_workload SET job_uid='foreign-job' WHERE pod_uid='pod-two'");
        }
        Expected supplied = switch (changed) {
            case "revision" -> new Expected(e.runId(), e.attemptId(), e.runRevision() + 1, e.fence());
            case "fence" -> new Expected(e.runId(), e.attemptId(), e.runRevision(), e.fence() + 1);
            case "attempt" -> new Expected(e.runId(), UUID.randomUUID(), e.runRevision(), e.fence());
            case "run" -> new Expected(UUID.randomUUID(), e.attemptId(), e.runRevision(), e.fence());
            default -> e;
        };
        Set<WorkloadRef> suppliedRows = switch (changed) {
            case "missing-pod" -> Set.of(FIRST);
            case "extra-pod" -> Set.of(FIRST, SECOND, new WorkloadRef("cluster-one", "extra"));
            case "cluster" -> Set.of(FIRST, new WorkloadRef("foreign-cluster", SECOND.podUid()));
            default -> ALL;
        };
        String before = fingerprint();

        // when
        Transition<Void> result = cleanup
                .complete(supplied, changed.equals("job") ? "foreign" : JOB, suppliedRows, budget());

        // then
        assertThat(result.status()).isEqualTo(Status.DENIED);
        assertThat(fingerprint()).isEqualTo(before);
        assertThat(runtime.outstandingWorkloads(runId)).isEqualTo(2);
    }

    @ParameterizedTest
    @ValueSource(strings = {
            "expected",
            "job-null",
            "job-empty",
            "job-long",
            "job-nul",
            "rows-null",
            "row-null",
            "rows-bound",
            "surrogate"})
    void deniesWithoutMutation_whenInputIsInvalid(String invalid) throws Exception {
        // given
        var e = expected(fence());
        String job = switch (invalid) {
            case "job-null" -> null;
            case "job-empty" -> " ";
            case "job-long" -> "a".repeat(129);
            case "job-nul" -> "bad\u0000job";
            default -> JOB;
        };
        Set<WorkloadRef> rows = new HashSet<>(ALL);
        if (invalid.equals("rows-null")) {
            rows = null;
        } else if (invalid.equals("row-null")) {
            rows.add(null);
        } else if (invalid.equals("rows-bound")) {
            for (int i = 0; i < 17; i++) {
                rows.add(new WorkloadRef("cluster-one", "extra-" + i));
            }
        } else if (invalid.equals("surrogate")) {
            rows = Set.of(new WorkloadRef("cluster-one", "bad\uD800"));
        }
        String before = fingerprint();

        // when
        Transition<Void> result = cleanup.complete(invalid.equals("expected") ? null : e, job, rows, budget());

        // then
        assertThat(result.status()).isEqualTo(Status.DENIED);
        assertThat(fingerprint()).isEqualTo(before);
    }

    @Test
    void deniesCompletion_whenAttemptIsNotFenced() throws Exception {
        // given
        String before = fingerprint();

        // when
        Transition<Void> result = cleanup.complete(expected(current()), JOB, ALL, budget());

        // then
        assertThat(result.status()).isEqualTo(Status.DENIED);
        assertThat(fingerprint()).isEqualTo(before);
    }

    @Test
    void deniesReplay_whenARecordedWorkloadIsNotClosed() throws Exception {
        // given
        var e = expected(fence());
        assertThat(cleanup.complete(e, JOB, ALL, budget()).status()).isEqualTo(Status.APPLIED);
        execute("UPDATE ai_runtime_workload SET state='REGISTERED' WHERE pod_uid='pod-two'");
        String before = fingerprint();

        // when
        Transition<Void> result = cleanup.complete(e, JOB, ALL, budget());

        // then
        assertThat(result.status()).isEqualTo(Status.DENIED);
        assertThat(fingerprint()).isEqualTo(before);
    }

    @ParameterizedTest
    @ValueSource(strings = {"disabled", "missing", "expired-run"})
    void completesHousekeeping_whenReadinessOrRunDeadlineIsUnavailable(String state) throws Exception {
        // given
        var e = expected(fence());
        if (state.equals("disabled")) {
            assertThat(kernel.disableControl(kernel.control().orElseThrow().version()).status())
                    .isEqualTo(Status.APPLIED);
        } else if (state.equals("missing")) {
            execute("DELETE FROM ai_runtime_control");
        } else {
            execute("UPDATE ai_runtime_run SET run_deadline=clock_timestamp()-interval '1 second'");
        }

        // when
        Transition<Void> result = cleanup.complete(e, JOB, ALL, budget());

        // then
        assertThat(result.status()).isEqualTo(Status.APPLIED);
        assertThat(current().launch().cleanup()).isEqualTo(CleanupState.DONE);
    }

    @Test
    void throwsUnavailable_whenOperationBudgetHasExpired() throws Exception {
        // given
        var e = expected(fence());
        var expired = AiRuntimeOperationBudget.start(Duration.ofNanos(1));
        org.awaitility.Awaitility
                .await()
                .pollInSameThread()
                .atMost(Duration.ofSeconds(1))
                .untilAsserted(() -> assertThatThrownBy(expired::remaining)
                        .isInstanceOf(AiRuntimeOperationBudget.Unavailable.class));
        String before = fingerprint();

        // when
        org.assertj.core.api.ThrowableAssert.ThrowingCallable complete = () -> cleanup.complete(e, JOB, ALL, expired);

        // then
        assertThatThrownBy(complete).isInstanceOf(AiRuntimeOperationBudget.Unavailable.class);
        assertThat(fingerprint()).isEqualTo(before);
    }

    @Test
    void releasesPodReservation_whenExactCleanupReachesDone() throws Exception {
        // given
        var fenced = recoverableFence();
        var next = nextAttempt(fenced);
        String before = fingerprint();
        assertThat(kernel.replace(expected(fenced), next).status()).isEqualTo(Status.LIMIT_REACHED);
        assertThat(cleanup.complete(expected(fenced), JOB, Set.of(FIRST), budget()).status()).isEqualTo(Status.DENIED);
        assertThat(runtime.outstandingWorkloads(runId)).isEqualTo(2);
        assertThat(fingerprint()).isEqualTo(before);

        // when
        Transition<Void> result = cleanup.complete(expected(fenced), JOB, ALL, budget());

        // then
        assertThat(result.status()).isEqualTo(Status.APPLIED);
        assertThat(runtime.outstandingWorkloads(runId)).isZero();
        assertThat(kernel.replace(expected(fenced), next).status()).isEqualTo(Status.APPLIED);
        assertThat(current().attempt().spec().attemptId()).isEqualTo(next.attemptId());
    }

    @Test
    void deniesCompletion_whenAttemptHasBeenReplaced() throws Exception {
        // given
        execute("DELETE FROM ai_runtime_workload WHERE pod_uid='pod-two'");
        var old = recoverableFence();
        assertThat(kernel.replace(expected(old), nextAttempt(old)).status()).isEqualTo(Status.APPLIED);
        String before = fingerprint();

        // when
        Transition<Void> result = cleanup.complete(expected(old), JOB, Set.of(FIRST), budget());

        // then
        assertThat(result.status()).isEqualTo(Status.DENIED);
        assertThat(fingerprint()).isEqualTo(before);
        assertThat(runtime.outstandingWorkloads(runId)).isEqualTo(1);
    }

    @ParameterizedTest
    @ValueSource(strings = {"job", "launch", "pod-row"})
    void deniesCompletion_whenRecordedMetadataIsMissing(String missing) throws Exception {
        // given
        var e = expected(fence());
        if (missing.equals("job")) {
            execute("UPDATE ai_runtime_launch SET job_uid=NULL");
        } else if (missing.equals("launch")) {
            execute("DELETE FROM ai_runtime_workload");
            execute("DELETE FROM ai_runtime_launch");
        } else {
            execute("DELETE FROM ai_runtime_workload WHERE pod_uid='pod-two'");
        }
        String before = fingerprint();

        // when
        Transition<Void> result = cleanup.complete(e, JOB, ALL, budget());

        // then
        assertThat(result.status()).isEqualTo(Status.DENIED);
        assertThat(fingerprint()).isEqualTo(before);
    }

    @Test
    void preservesIdentifiers_whenPodUidContainsQuotedUnicode() throws Exception {
        // given
        execute("DELETE FROM ai_runtime_workload");
        var ref = new WorkloadRef("cluster-one", "quoted-'\\\"-λ");
        assertThat(kernel.observe(observation(current(), ref, 3, true)).status()).isEqualTo(Status.APPLIED);
        var e = expected(fence());

        // when
        Transition<Void> result = cleanup.complete(e, JOB, Set.of(ref), budget());

        // then
        assertThat(result.status()).isEqualTo(Status.APPLIED);
        assertThat(current().workloads()).singleElement().satisfies(row -> assertThat(row.ref()).isEqualTo(ref));
    }

    @Test
    void rejectsFinalWrite_whenSqlOperationCutoffHasPassed() throws Exception {
        // given
        var e = expected(fence());
        var at = AiRuntimeFixture.now(source);
        String rows = com.otilm.core.serialization.ObjectMapperFactory.canonical().writeValueAsString(ALL);
        String before = fingerprint();
        var transaction = new org.springframework.transaction.support.TransactionTemplate(transactions);

        // when
        Integer affected = transaction.execute(status -> {
            runtime.configureTransaction(1000);
            return repository.complete(e, JOB, rows, at, at.minusSeconds(1));
        });

        // then
        assertThat(affected).isZero();
        assertThat(fingerprint()).isEqualTo(before);
    }

    @Test
    void rollsBackCompletion_whenMetadataDriftsAtPersistenceBoundary() throws Exception {
        // given
        var e = expected(fence());
        String before = fingerprint();
        var reached = new java.util.concurrent.atomic.AtomicBoolean();
        var selected = cleanupProxy(call -> {
            Object value = call.proceed();
            if (call.getMethod().getName().equals("current")) {
                assertThat(value).isEqualTo(java.util.Optional.of("DUE"));
                assertThat(entityManager
                        .createNativeQuery(
                                "UPDATE core.ai_runtime_workload SET job_uid='changed' WHERE pod_uid='pod-two'")
                        .executeUpdate()).isEqualTo(1);
                reached.set(true);
            }
            return value;
        });
        var writer = writer(runtime, selected);
        var budget = budget();

        // when
        org.assertj.core.api.ThrowableAssert.ThrowingCallable complete = () -> writer.complete(e, JOB, ALL, budget);

        // then
        assertThatThrownBy(complete).isInstanceOf(AiRuntimeOperationBudget.Unavailable.class);
        assertThat(reached.get()).isTrue();
        assertThat(fingerprint()).isEqualTo(before);
        assertThat(runtime.outstandingWorkloads(runId)).isEqualTo(2);
    }

    @ParameterizedTest
    @ValueSource(strings = {"run", "attempt", "launch", "workload"})
    void boundsSqlWaitWithoutRelease_whenAnOwnedRowIsLocked(String boundary) throws Exception {
        // given
        var e = expected(fence());
        String before = fingerprint();
        var pid = new java.util.concurrent.atomic.AtomicInteger();
        var selected = runtimeProxy(call -> {
            Object value = call.proceed();
            if (call.getMethod().getName().equals("configureTransaction")) {
                pid
                        .set(((Number) entityManager.createNativeQuery("SELECT pg_backend_pid()").getSingleResult())
                                .intValue());
            }
            return value;
        });
        var writer = writer(selected, repository);
        String sql = switch (boundary) {
            case "run" -> "SELECT uuid FROM core.ai_runtime_run WHERE uuid=? FOR UPDATE";
            case "attempt" -> "SELECT uuid FROM core.ai_runtime_attempt WHERE uuid=? FOR UPDATE";
            case "launch" -> "SELECT attempt_uuid FROM core.ai_runtime_launch WHERE attempt_uuid=? FOR UPDATE";
            default ->
                "SELECT pod_uid FROM core.ai_runtime_workload WHERE attempt_uuid=? AND pod_uid='pod-two' FOR UPDATE";
        };
        var executor = java.util.concurrent.Executors.newSingleThreadExecutor();
        try (var holder = source.getConnection(); var observer = source.getConnection()) {
            holder.setAutoCommit(false);
            int holderPid = physicalPid(holder);
            try (var statement = holder.prepareStatement(sql)) {
                statement.setObject(1, boundary.equals("run") ? e.runId() : e.attemptId());
                try (var rows = statement.executeQuery()) {
                    assertThat(rows.next()).isTrue();
                }
            }

            // when
            java.util.concurrent.Future<Throwable> result = executor
                    .submit(() -> org.assertj.core.api.Assertions
                            .catchThrowable(() -> writer
                                    .complete(e, JOB, ALL, AiRuntimeOperationBudget.start(Duration.ofMillis(300)))));
            org.awaitility.Awaitility
                    .await("Exact cleanup row waiter")
                    .pollInSameThread()
                    .pollDelay(Duration.ZERO)
                    .pollInterval(Duration.ofMillis(2))
                    .atMost(Duration.ofMillis(250))
                    .until(() -> {
                        if (pid.get() <= 0) {
                            return false;
                        }
                        try (var statement = observer.prepareStatement("SELECT ?=ANY(pg_blocking_pids(?))")) {
                            statement.setInt(1, holderPid);
                            statement.setInt(2, pid.get());
                            try (var rows = statement.executeQuery()) {
                                assertThat(rows.next()).isTrue();
                                return rows.getBoolean(1);
                            }
                        }
                    });
            // then
            assertThat(pid.get()).isPositive().isNotEqualTo(holderPid);
            org.awaitility.Awaitility
                    .await("Cleanup SQL ends before the legacy timeout")
                    .pollInSameThread()
                    .pollDelay(Duration.ZERO)
                    .atMost(Duration.ofMillis(650))
                    .untilAsserted(() -> assertThat(result.isDone()).isTrue());
            var failure = result.get(1, java.util.concurrent.TimeUnit.SECONDS);
            assertThat(failure).isNotNull();
            assertThat(sqlState(failure)).isIn("55P03", "57014");
            assertThat(fingerprint()).isEqualTo(before);
            assertThat(runtime.outstandingWorkloads(runId)).isEqualTo(2);
        } finally {
            executor.shutdownNow();
            assertThat(executor.awaitTermination(3, java.util.concurrent.TimeUnit.SECONDS)).isTrue();
        }
    }

    @ParameterizedTest
    @ValueSource(strings = {"BEFORE", "AFTER"})
    void rollsBackCompletion_whenChildUpdateOrStatementReturnExceedsCutoff(String triggerPhase) throws Exception {
        // given
        var e = expected(fence());
        try {
            execute("""
                    CREATE FUNCTION core.f03_cleanup_delay() RETURNS trigger LANGUAGE plpgsql AS $$
                    BEGIN
                        PERFORM set_config('ilm.cleanup_rows',
                            (current_setting('ilm.cleanup_rows')::int+1)::text,true);
                        PERFORM pg_sleep(0.3);
                        RETURN NEW;
                    END $$
                    """);
            execute("CREATE TRIGGER f03_cleanup_delay " + triggerPhase
                    + " UPDATE ON core.ai_runtime_workload FOR EACH ROW EXECUTE FUNCTION core.f03_cleanup_delay()");
            String before = fingerprint();
            var entered = new java.util.concurrent.atomic.AtomicBoolean();
            var returnedExpected = new java.util.concurrent.atomic.AtomicBoolean();
            var selected = cleanupProxy(call -> {
                if (!call.getMethod().getName().equals("complete")) {
                    return call.proceed();
                }
                entered.set(true);
                // Explicit timeout fault reaches the controlled BEFORE/AFTER trigger; never a production budget change.
                entityManager.createNativeQuery("SELECT set_config('statement_timeout','5s',true)").getSingleResult();
                entityManager.createNativeQuery("SELECT set_config('ilm.cleanup_rows','0',true)").getSingleResult();
                Object value = call.proceed();
                assertThat(
                        entityManager.createNativeQuery("SELECT current_setting('ilm.cleanup_rows')").getSingleResult())
                        .isEqualTo("2");
                assertThat(value).isEqualTo(triggerPhase.equals("BEFORE") ? 0 : 1);
                returnedExpected.set(true);
                return value;
            });
            var writer = writer(runtime, selected);
            var budget = AiRuntimeOperationBudget.start(Duration.ofMillis(500));
            // when
            org.assertj.core.api.ThrowableAssert.ThrowingCallable complete = () -> writer.complete(e, JOB, ALL, budget);

            // then
            assertThatThrownBy(complete).isInstanceOf(AiRuntimeOperationBudget.Unavailable.class);
            assertThat(entered.get()).isTrue();
            assertThat(returnedExpected.get()).isTrue();
            assertThat(fingerprint()).isEqualTo(before);
            assertThat(runtime.outstandingWorkloads(runId)).isEqualTo(2);
        } finally {
            execute("DROP TRIGGER IF EXISTS f03_cleanup_delay ON core.ai_runtime_workload");
            execute("DROP FUNCTION IF EXISTS core.f03_cleanup_delay()");
        }
    }

    @Test
    void logsFixedMetadata_whenCleanupIsDenied() throws Exception {
        // given
        var e = expected(fence());
        var logger = (ch.qos.logback.classic.Logger) org.slf4j.LoggerFactory.getLogger(AiRuntimeCleanupWriter.class);
        var original = logger.getLevel();
        var logs = new ch.qos.logback.core.read.ListAppender<ch.qos.logback.classic.spi.ILoggingEvent>();
        logs.start();
        logger.addAppender(logs);
        logger.setLevel(ch.qos.logback.classic.Level.DEBUG);
        try {

            // when
            Transition<Void> result = cleanup.complete(e, "SYNTHETIC_PRIVATE_JOB_CANARY", ALL, budget());

            // then
            assertThat(result.status()).isEqualTo(Status.DENIED);
            assertThat(logs.list).isNotEmpty().allSatisfy(event -> {
                assertThat(event.getFormattedMessage())
                        .isEqualTo("AI runtime operation=cleanup status=DENIED run=" + runId);
                assertThat(event.getThrowableProxy()).isNull();
            });
        } finally {
            logger.detachAppender(logs);
            logger.setLevel(original);
            logs.stop();
        }
    }

    @Test
    void throwsUnavailable_whenConservativeDatabaseCutoffPassesBeforeJavaBudget() throws Exception {
        // given
        Expected binding = expected(fence());
        String before = fingerprint();
        var clockReads = new java.util.concurrent.atomic.AtomicInteger();
        var reachedCurrent = new java.util.concurrent.atomic.AtomicBoolean();
        var remainingAtCurrent = new java.util.concurrent.atomic.AtomicLong();
        var classificationEnteredWith = new java.util.concurrent.atomic.AtomicLong();
        var classificationReturnedWith = new java.util.concurrent.atomic.AtomicLong();
        var cutoff = new java.util.concurrent.atomic.AtomicReference<java.time.Instant>();
        var classificationTime = new java.util.concurrent.atomic.AtomicReference<java.time.Instant>();
        var budget = AiRuntimeOperationBudget.start(Duration.ofMillis(1500));
        var selectedRuntime = runtimeProxy(call -> {
            if (!call.getMethod().getName().equals("decisionTime")) {
                return call.proceed();
            }
            int clockRead = clockReads.incrementAndGet();
            if (clockRead == 2) {
                classificationEnteredWith.set(budget.remaining().toMillis());
            }
            Object value = call.proceed();
            if (clockRead == 1) {
                // Delay only the first real clock result, never the later expiry classification read.
                entityManager.createNativeQuery("SELECT pg_sleep(0.6)").getSingleResult();
            } else if (clockRead == 2) {
                classificationTime.set((java.time.Instant) value);
                classificationReturnedWith.set(budget.remaining().toMillis());
            }
            return value;
        });
        var selectedCleanup = cleanupProxy(call -> {
            if (!call.getMethod().getName().equals("current")) {
                return call.proceed();
            }
            cutoff.set((java.time.Instant) call.getArguments()[3]);
            entityManager.createNativeQuery("SELECT pg_sleep(0.5)").getSingleResult();
            Object value = call.proceed();
            reachedCurrent.set(true);
            remainingAtCurrent.set(budget.remaining().toMillis());
            return value;
        });
        var selectedWriter = writer(selectedRuntime, selectedCleanup);

        // when
        org.assertj.core.api.ThrowableAssert.ThrowingCallable complete = () -> selectedWriter
                .complete(binding, JOB, ALL, budget);

        // then
        assertThatThrownBy(complete).isInstanceOf(AiRuntimeOperationBudget.Unavailable.class);
        assertThat(clockReads.get()).isEqualTo(2);
        assertThat(reachedCurrent.get()).isTrue();
        assertThat(remainingAtCurrent.get()).isPositive();
        assertThat(classificationEnteredWith.get()).isPositive();
        assertThat(classificationReturnedWith.get()).isPositive();
        assertThat(classificationTime.get()).isAfterOrEqualTo(cutoff.get());
        assertThat(fingerprint()).isEqualTo(before);
        assertThat(runtime.outstandingWorkloads(runId)).isEqualTo(2);
    }

    @ParameterizedTest
    @ValueSource(strings = {"job", "subset"})
    void deniesDoneReplay_whenTheSuppliedBindingNoLongerMatches(String mismatch) throws Exception {
        // given
        Expected binding = expected(fence());
        assertThat(cleanup.complete(binding, JOB, ALL, budget()).status()).isEqualTo(Status.APPLIED);
        String before = fingerprint();
        String requestedJob = mismatch.equals("job") ? "foreign-job" : JOB;
        Set<WorkloadRef> requestedRefs = mismatch.equals("subset") ? Set.of(FIRST) : ALL;

        // when
        Transition<Void> result = cleanup.complete(binding, requestedJob, requestedRefs, budget());

        // then
        assertThat(result.status()).isEqualTo(Status.DENIED);
        assertThat(fingerprint()).isEqualTo(before);
        assertThat(runtime.outstandingWorkloads(runId)).isZero();
        Transition<Void> replay = cleanup.complete(binding, JOB, ALL, budget());
        assertThat(replay.status()).isEqualTo(Status.REPLAY);
        assertThat(fingerprint()).isEqualTo(before);
    }

    // ── Helpers ───────────────────────────────────────────────────────────────

    private RunSnapshot recoverableFence() throws Exception {
        assertThat(kernel.bootstrap(expected(current()), FIRST).status()).isEqualTo(Status.APPLIED);
        UUID attempt = current().attempt().spec().attemptId();
        try (var c = source.getConnection(); PreparedStatement statement = c.prepareStatement("""
                WITH cutoff AS (SELECT clock_timestamp()-interval '1 second' AS until)
                UPDATE ai_runtime_attempt SET lease_until=cutoff.until,last_heartbeat_lease=cutoff.until
                FROM cutoff WHERE uuid=?
                """)) {
            statement.setObject(1, attempt);
            assertThat(statement.executeUpdate()).isEqualTo(1);
        }
        assertThat(kernel.expire(expected(current())).status()).isEqualTo(Status.APPLIED);
        return current();
    }

    private static AttemptSpec nextAttempt(RunSnapshot run) {
        var old = run.attempt().spec();
        return new AttemptSpec(UUID.randomUUID(), old.launchDeadline(), old.maxDeadline(), old.imageDigest(),
                old.profileRevision(), old.securityRevision(), old.trustRevision(), old.protocol(), old.launch());
    }

    private static int physicalPid(java.sql.Connection connection) throws Exception {
        try (var statement = connection.createStatement();
                var rows = statement.executeQuery("SELECT pg_backend_pid()")) {
            assertThat(rows.next()).isTrue();
            return rows.getInt(1);
        }
    }

    private static String sqlState(Throwable failure) {
        for (Throwable current = failure; current != null; current = current.getCause()) {
            if (current instanceof java.sql.SQLException sql) {
                return sql.getSQLState();
            }
        }
        return "NO_SQL_STATE";
    }

    private AiRuntimeRepository runtimeProxy(org.aopalliance.intercept.MethodInterceptor advice) {
        var factory = new org.springframework.aop.framework.ProxyFactory(runtime);
        factory.addAdvice(advice);
        return (AiRuntimeRepository) factory.getProxy();
    }

    private com.otilm.core.dao.repository.ai.AiRuntimeCleanupRepository cleanupProxy(
            org.aopalliance.intercept.MethodInterceptor advice) {
        var factory = new org.springframework.aop.framework.ProxyFactory(repository);
        factory.addAdvice(advice);
        return (com.otilm.core.dao.repository.ai.AiRuntimeCleanupRepository) factory.getProxy();
    }

    private AiRuntimeCleanupWriter writer(AiRuntimeRepository selectedRuntime,
            com.otilm.core.dao.repository.ai.AiRuntimeCleanupRepository selectedCleanup) {
        var factory = new org.springframework.aop.framework.ProxyFactory(
                new AiRuntimeCleanupWriter(selectedRuntime, selectedCleanup));
        factory.setProxyTargetClass(true);
        factory
                .addAdvice(new org.springframework.transaction.interceptor.TransactionInterceptor(transactions,
                        new org.springframework.transaction.annotation.AnnotationTransactionAttributeSource()));
        return (AiRuntimeCleanupWriter) factory.getProxy();
    }

    private RunSnapshot fence() {
        assertThat(kernel.cancel(runId).status()).isEqualTo(Status.APPLIED);
        return current();
    }

    private RunSnapshot current() {
        return kernel.snapshot(runId).orElseThrow();
    }

    private static AiRuntimeOperationBudget budget() {
        return AiRuntimeOperationBudget.start();
    }

    private void execute(String sql) throws Exception {
        try (var c = source.getConnection(); var statement = c.createStatement()) {
            statement.execute(sql);
        }
    }

    private String fingerprint() throws Exception {
        try (var c = source.getConnection(); var statement = c.createStatement(); var rows = statement.executeQuery("""
                SELECT encode(sha256(convert_to(jsonb_build_array(
                    (SELECT jsonb_agg(to_jsonb(r) ORDER BY uuid) FROM ai_runtime_run r),
                    (SELECT jsonb_agg(to_jsonb(a) ORDER BY uuid) FROM ai_runtime_attempt a),
                    (SELECT jsonb_agg(to_jsonb(l) ORDER BY attempt_uuid) FROM ai_runtime_launch l),
                    (SELECT jsonb_agg(to_jsonb(w) ORDER BY cluster,pod_uid) FROM ai_runtime_workload w)
                )::text,'UTF8')),'hex')
                """)) {
            assertThat(rows.next()).isTrue();
            return rows.getString(1);
        }
    }
}
