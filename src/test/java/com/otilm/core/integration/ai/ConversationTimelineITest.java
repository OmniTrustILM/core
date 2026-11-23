package com.otilm.core.integration.ai;

import com.otilm.api.model.core.certificate.CertificateState;
import com.otilm.api.model.core.certificate.CertificateValidationStatus;
import com.otilm.core.dao.entity.RaProfile;
import com.otilm.core.dao.entity.X509CertificateEntity;
import com.otilm.core.dao.repository.CertificateRepository;
import com.otilm.core.dao.repository.RaProfileRepository;
import com.otilm.core.feasibility.ConversationStreamAuthorization;
import com.otilm.core.feasibility.ConversationStreamFixture;
import com.otilm.core.feasibility.ConversationStreamProofConfiguration;
import com.otilm.core.feasibility.ConversationTimeline;
import com.otilm.core.security.authn.client.AuthenticationCache;
import com.otilm.core.util.ai.AuthoritativePolicyProofSupport;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Proxy;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;
import java.util.function.Predicate;
import javax.sql.DataSource;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.annotation.Import;
import org.springframework.dao.DataAccessException;
import org.springframework.jdbc.core.JdbcOperations;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.support.TransactionSynchronizationManager;
import org.springframework.transaction.support.TransactionTemplate;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.assertj.core.api.Assertions.catchThrowable;

@SpringBootTest
@Import(ConversationStreamProofConfiguration.class)
class ConversationTimelineITest extends AuthoritativePolicyProofSupport {
    private static final UUID ACTOR = UUID.fromString("00000000-0000-4000-8000-000000000071");
    private static final UUID OTHER = UUID.fromString("00000000-0000-4000-8000-000000000072");
    private static final byte[] BODY = "synthetic command".getBytes(StandardCharsets.UTF_8);
    private static final Instant FUTURE = Instant.parse("2100-01-01T00:00:00Z");
    @Autowired
    private DataSource dataSource;
    @Autowired
    private ConversationTimeline timeline;
    @Autowired
    private ConversationStreamFixture fixture;
    @Autowired
    private ConversationStreamAuthorization authorization;
    @Autowired
    private CertificateRepository certificates;
    @Autowired
    private RaProfileRepository profiles;
    @Autowired
    private AuthenticationCache authenticationCache;
    @Autowired
    private PlatformTransactionManager transactions;
    private JdbcTemplate jdbc;
    private ConversationTimeline.Scope scope;
    private UUID first;
    private UUID second;

    @BeforeEach
    void seedLedger() throws Exception {
        AUTHORITY.reset();
        authenticationCache.evictAll();
        authorizationCache.evictAll();
        jdbc = new JdbcTemplate(dataSource);
        jdbc
                .execute("TRUNCATE f07_proof.timeline_event, f07_proof.command_record, f07_proof.run_record, "
                        + "f07_proof.retained_certificate, f07_proof.conversation");
        RaProfile profile = new RaProfile();
        profile.setName("Synthetic F07 " + UUID.randomUUID());
        profile.setEnabled(true);
        profile.setValidationEnabled(false);
        profile = profiles.saveAndFlush(profile);
        first = certificate(profile);
        second = certificate(profile);
        UUID conversation = UUID.randomUUID();
        jdbc
                .update("INSERT INTO f07_proof.conversation VALUES (?,?,?,1,0,?,NULL)", conversation, ACTOR,
                        profile.getUuid(), "synthetic protected title");
        jdbc.update("INSERT INTO f07_proof.retained_certificate VALUES (?,?)", conversation, first);
        scope = new ConversationTimeline.Scope(conversation, ACTOR, profile.getUuid(), 1, Set.of(first));
        allow(Set.of(first, second));
        fixture.afterAuthorization(() -> {
        });
        authorization.beforeInvocation(() -> {
        });
    }

    @AfterEach
    void releaseBarriers() {
        fixture.afterAuthorization(() -> {
        });
        authorization.beforeInvocation(() -> {
        });
        AUTHORITY.beforeRequest = (path, body) -> {
        };
    }

    @Test
    void commandPersistsAndReplaysOneLogicalRun() {
        var firstRun = timeline.command(scope, ConversationTimeline.CommandKind.START, "first-command", BODY);
        assertThat(count("run_record")).isEqualTo(1);
        assertThat(firstRun).isPresent();
        var replay = timeline
                .command(scope, ConversationTimeline.CommandKind.START, "first-command", BODY)
                .orElseThrow();
        assertThat(replay.runId()).isEqualTo(firstRun.orElseThrow().runId());
        assertThat(replay.replay()).isTrue();
        assertThat(count("run_record")).isEqualTo(1);
        assertThat(count("command_record")).isEqualTo(1);
    }

    @Test
    void changedReplayAndSecondActiveRunCannotMutateLedger() {
        run();
        assertThatThrownBy(
                () -> timeline.command(scope, ConversationTimeline.CommandKind.START, "start", new byte[]{7}))
                .isInstanceOf(IllegalStateException.class);
        assertThatThrownBy(() -> timeline.command(scope, ConversationTimeline.CommandKind.FOLLOW_UP, "other", BODY))
                .isInstanceOf(IllegalStateException.class);
        assertThat(count("run_record")).isEqualTo(1);
        assertThat(count("command_record")).isEqualTo(1);
    }

    @Test
    void staleAuthorizedRevisionCannotLookupOrCreateACommand() {
        jdbc.update("UPDATE f07_proof.conversation SET scope_revision=2 WHERE uuid=?", scope.conversationId());
        assertThat(timeline.command(scope, ConversationTimeline.CommandKind.START, "start", BODY)).isEmpty();
        assertThat(count("run_record")).isZero();
        assertThat(count("command_record")).isZero();
    }

    @Test
    void cancellationAndCompletionPreserveCommittedTerminalTruth() {
        UUID run = run();
        assertThat(timeline.cancel(scope, run, "cancel", BODY).orElseThrow().state())
                .isEqualTo(ConversationTimeline.RunState.CANCELLED);
        assertThat(timeline.complete(run).state()).isEqualTo(ConversationTimeline.RunState.CANCELLED);
        assertThat(timeline.cancel(scope, run, "cancel", BODY).orElseThrow().replay()).isTrue();
        UUID next = timeline
                .command(scope, ConversationTimeline.CommandKind.FOLLOW_UP, "next", BODY)
                .orElseThrow()
                .runId();
        assertThat(timeline.complete(next).state()).isEqualTo(ConversationTimeline.RunState.COMPLETE);
        assertThat(timeline.cancel(scope, next, "late-cancel", BODY).orElseThrow().state())
                .isEqualTo(ConversationTimeline.RunState.COMPLETE);
        assertThat(count("run_record")).isEqualTo(2);
    }

    @Test
    void twoActualWritersSerializeBeforeActiveRunDecision() throws Exception {
        CountDownLatch locked = new CountDownLatch(1);
        CountDownLatch release = new CountDownLatch(1);
        AtomicInteger leaderPid = new AtomicInteger();
        AtomicInteger waiterPid = new AtomicInteger();
        ConversationTimeline leader = pausedTimeline(
                sql -> sql.contains("FROM f07_proof.conversation") && sql.endsWith("FOR UPDATE"), locked, release,
                leaderPid);
        ConversationTimeline follower = observedTimeline(waiterPid);
        try (var pool = Executors.newFixedThreadPool(2)) {
            var a = pool.submit(() -> leader.command(scope, ConversationTimeline.CommandKind.START, "a", BODY));
            assertThat(locked.await(3, TimeUnit.SECONDS)).isTrue();
            var b = pool
                    .submit(() -> catchThrowable(
                            () -> follower.command(scope, ConversationTimeline.CommandKind.START, "b", BODY)));
            try {
                awaitDatabaseWaiter(waiterPid, leaderPid);
                assertThat(a.isDone()).isFalse();
                assertThat(b.isDone()).isFalse();
            } finally {
                release.countDown();
            }
            assertThat(a.get(5, TimeUnit.SECONDS)).isPresent();
            assertThat(b.get(5, TimeUnit.SECONDS))
                    .isInstanceOf(IllegalStateException.class)
                    .hasMessage("Command conflict");
        } finally {
            release.countDown();
        }
        assertThat(count("run_record")).isEqualTo(1);
        assertThat(count("command_record")).isEqualTo(1);
    }

    @Test
    void allocatedCursorCannotSkipAnEarlierUncommittedEntry() throws Exception {
        UUID run = run();
        CountDownLatch allocated = new CountDownLatch(1);
        CountDownLatch release = new CountDownLatch(1);
        AtomicInteger leaderPid = new AtomicInteger();
        AtomicInteger waiterPid = new AtomicInteger();
        ConversationTimeline leader = pausedTimeline(
                sql -> sql.startsWith("UPDATE f07_proof.conversation SET next_ordinal"), allocated, release, leaderPid);
        ConversationTimeline follower = observedTimeline(waiterPid);
        try (var pool = Executors.newFixedThreadPool(2)) {
            var a = pool
                    .submit(() -> leader
                            .append(scope.conversationId(), run, "first committed canary", Set.of(first), FUTURE));
            assertThat(allocated.await(3, TimeUnit.SECONDS)).isTrue();
            var b = pool
                    .submit(() -> follower
                            .append(scope.conversationId(), run, "second committed canary", Set.of(first), FUTURE));
            try {
                awaitDatabaseWaiter(waiterPid, leaderPid);
                assertThat(count("timeline_event")).isZero();
                assertThat(b.isDone()).isFalse();
            } finally {
                release.countDown();
            }
            var firstEvent = a.get(5, TimeUnit.SECONDS);
            var secondEvent = b.get(5, TimeUnit.SECONDS);
            assertThat(firstEvent.ordinal()).isEqualTo(1);
            assertThat(secondEvent.ordinal()).isEqualTo(2);
            var batch = timeline.read(scope.conversationId(), 1, Optional.of(firstEvent.cursor()), 8).orElseThrow();
            assertThat(batch.events())
                    .extracting(ConversationTimeline.Event::value)
                    .containsExactly("second committed canary");
            assertThat(batch.events().getFirst().cursor()).isEqualTo(secondEvent.cursor());
            assertThat(batch.count()).isEqualTo(2);
        } finally {
            release.countDown();
        }
    }

    @Test
    void actualRetainedScopeAuthorizationProtectsEntriesAndMetadata() {
        UUID run = run();
        timeline.append(scope.conversationId(), run, "protected entry canary", Set.of(first), FUTURE);
        AtomicReference<ConversationTimeline.Batch> result = new AtomicReference<>();
        assertThat(catchThrowable(() -> result.set(fixture.read(ACTOR, scope.conversationId(), Optional.empty(), 8))))
                .isNull();
        assertThat(result.get().events())
                .extracting(ConversationTimeline.Event::value)
                .containsExactly("protected entry canary");
        assertThat(result.get().title()).isEqualTo("synthetic protected title");
        assertThat(result.get().count()).isEqualTo(1);
        assertThat(AUTHORITY.count("/auth")).isPositive();
        assertThat(AUTHORITY.count("/v1/data/method")).isPositive();
        assertThat(AUTHORITY.count("/v1/data/objects")).isZero();
        assertThat(AUTHORITY.exchanges
                .stream()
                .filter(e -> e.path().equals("/v1/data/method"))
                .map(e -> e.request().at("/input/requestedResource/name").asText()))
                .containsExactly("raProfiles", "certificates");
        assertThat(AUTHORITY.exchanges
                .stream()
                .filter(e -> e.path().equals("/v1/data/method"))
                .map(e -> e.request().at("/input/requestedResource/uuids/0").asText()))
                .containsExactly(scope.raProfileId().toString(), first.toString());
    }

    @Test
    void foreignOwnerIsDeniedBeforeCursorOrReplayLookup() {
        UUID conversationId = scope.conversationId();
        Optional<UUID> unknownCursor = Optional.of(UUID.randomUUID());
        run();
        AUTHORITY.exchanges.clear();
        assertThatThrownBy(() -> fixture.read(OTHER, conversationId, unknownCursor, 8))
                .isInstanceOf(AccessDeniedException.class);
        assertThatThrownBy(
                () -> fixture.command(OTHER, conversationId, ConversationTimeline.CommandKind.START, "start", BODY))
                .isInstanceOf(AccessDeniedException.class);
        assertThat(AUTHORITY.exchanges).isEmpty();
        assertThat(count("command_record")).isEqualTo(1);
    }

    @Test
    void warmIdempotencyReplayStillRequiresCurrentAuthorization() throws Exception {
        UUID conversationId = scope.conversationId();
        var accepted = fixture.command(ACTOR, conversationId, ConversationTimeline.CommandKind.START, "start", BODY);
        allow(Set.of());
        assertThatThrownBy(
                () -> fixture.command(ACTOR, conversationId, ConversationTimeline.CommandKind.START, "start", BODY))
                .isInstanceOf(AccessDeniedException.class);
        assertThat(count("command_record")).isEqualTo(1);
        assertThat(jdbc.queryForObject("SELECT uuid FROM f07_proof.run_record", UUID.class))
                .isEqualTo(accepted.runId());
    }

    @Test
    void revisionBarrierReauthorizesAddedRequirementAndSuppressesRevokedCanary() throws Exception {
        UUID conversationId = scope.conversationId();
        Optional<UUID> noCursor = Optional.empty();
        UUID run = run();
        AtomicBoolean produced = new AtomicBoolean();
        fixture.afterAuthorization(() -> {
            if (produced.compareAndSet(false, true)) {
                authorization
                        .require(ACTOR, new ConversationTimeline.Scope(conversationId, ACTOR, scope.raProfileId(), 1,
                                Set.of(second)));
                timeline.append(conversationId, run, "revoked B canary", Set.of(second), FUTURE);
                try {
                    allow(Set.of(first));
                } catch (Exception failure) {
                    throw new AssertionError(failure);
                }
            }
        });
        assertThatThrownBy(() -> fixture.read(ACTOR, conversationId, noCursor, 8))
                .isInstanceOf(AccessDeniedException.class);
        assertThat(produced).isTrue();
        assertThat(jdbc.queryForObject("SELECT scope_revision FROM f07_proof.conversation", Long.class)).isEqualTo(2);
        assertThat(jdbc.queryForObject("SELECT value FROM f07_proof.timeline_event", String.class))
                .isEqualTo("revoked B canary");
        assertThat(AUTHORITY.count("/auth")).isGreaterThanOrEqualTo(3);
        assertThat(secondCertificateVotes()).containsExactly(true, false);
    }

    @Test
    void stableRevisionRetryReturnsNewEntryOnlyAfterSecondActualAuthorization() {
        UUID run = run();
        AtomicInteger barriers = new AtomicInteger();
        fixture.afterAuthorization(() -> {
            if (barriers.incrementAndGet() == 1) {
                authorization
                        .require(ACTOR, new ConversationTimeline.Scope(scope.conversationId(), ACTOR,
                                scope.raProfileId(), 1, Set.of(second)));
                timeline.append(scope.conversationId(), run, "allowed B canary", Set.of(second), FUTURE);
            }
        });
        var batch = fixture.read(ACTOR, scope.conversationId(), Optional.empty(), 8);
        assertThat(barriers).hasValue(2);
        assertThat(batch.scope().revision()).isEqualTo(2);
        assertThat(batch.events()).extracting(ConversationTimeline.Event::value).containsExactly("allowed B canary");
        assertThat(AUTHORITY.count("/auth")).isGreaterThanOrEqualTo(3);
        assertThat(secondCertificateVotes()).containsExactly(true, true);
    }

    @Test
    void deletedRetainedSourceAndAuthorityLossDenyWholeBatch() {
        UUID conversationId = scope.conversationId();
        Optional<UUID> noCursor = Optional.empty();
        UUID run = run();
        timeline.append(conversationId, run, "retained source canary", Set.of(first), FUTURE);
        fixture.read(ACTOR, conversationId, noCursor, 8);
        AUTHORITY.authStatus = 503;
        assertThatThrownBy(() -> fixture.read(ACTOR, conversationId, noCursor, 8))
                .isInstanceOf(AccessDeniedException.class);
        AUTHORITY.authStatus = 200;
        AUTHORITY.opaUnavailable = true;
        assertThatThrownBy(() -> fixture.read(ACTOR, conversationId, noCursor, 8))
                .isInstanceOf(AccessDeniedException.class);
        AUTHORITY.opaUnavailable = false;
        certificates.deleteById(first);
        certificates.flush();
        assertThatThrownBy(() -> fixture.read(ACTOR, conversationId, noCursor, 8))
                .isInstanceOf(AccessDeniedException.class);
        assertThat(count("retained_certificate")).isEqualTo(1);
        assertThat(count("timeline_event")).isEqualTo(1);
    }

    @Test
    void actualAuthorityBoundaryHasNoTimelineTransactionAndAllowsConcurrentCommit() throws Exception {
        UUID conversationId = scope.conversationId();
        Optional<UUID> noCursor = Optional.empty();
        CountDownLatch entered = new CountDownLatch(1);
        CountDownLatch release = new CountDownLatch(1);
        AtomicBoolean firstCall = new AtomicBoolean(true);
        AUTHORITY.beforeRequest = (path, body) -> {
            if (path.equals("/auth") && firstCall.compareAndSet(true, false)) {
                entered.countDown();
                await(release);
            }
        };
        AtomicBoolean callerTransaction = new AtomicBoolean(true);
        authorization
                .beforeInvocation(
                        () -> callerTransaction.set(TransactionSynchronizationManager.isActualTransactionActive()));
        try (var pool = Executors.newSingleThreadExecutor()) {
            var reader = pool.submit(() -> fixture.read(ACTOR, conversationId, noCursor, 8));
            assertThat(entered.await(3, TimeUnit.SECONDS)).isTrue();
            assertThat(callerTransaction).isFalse();
            try {
                new TransactionTemplate(transactions).executeWithoutResult(status -> {
                    jdbc.execute("SET LOCAL lock_timeout='1s'");
                    jdbc
                            .update("UPDATE f07_proof.conversation SET title=? WHERE uuid=?",
                                    "committed while Auth paused", conversationId);
                });
            } finally {
                release.countDown();
            }
            assertThat(reader.get(10, TimeUnit.SECONDS).title()).isEqualTo("committed while Auth paused");
            assertThat(callerTransaction).isFalse();
        } finally {
            release.countDown();
        }
        long before = AUTHORITY.count("/auth");
        new TransactionTemplate(transactions)
                .executeWithoutResult(
                        status -> assertThatThrownBy(() -> fixture.read(ACTOR, conversationId, noCursor, 8))
                                .isInstanceOf(IllegalStateException.class));
        assertThat(AUTHORITY.count("/auth")).isEqualTo(before);
    }

    @Test
    void scopeLookupReadsOnlyOwnerAndRequirementsBeforeAuthorization() {
        UUID conversationId = scope.conversationId();
        List<String> observed = new ArrayList<>();
        ConversationTimeline measured = pausedTimeline(sql -> {
            observed.add(sql);
            return false;
        }, new CountDownLatch(0), new CountDownLatch(0));
        assertThat(measured.scope(ACTOR, conversationId).certificates()).containsExactly(first);
        assertThatThrownBy(() -> measured.scope(OTHER, conversationId)).isInstanceOf(AccessDeniedException.class);
        assertThat(observed.stream().filter(sql -> sql.contains("FROM f07_proof.conversation")))
                .hasSize(2)
                .allSatisfy(sql -> assertThat(sql).doesNotContain("title", "next_ordinal", "last_run_uuid"));
        assertThat(AUTHORITY.exchanges).isEmpty();
    }

    @Test
    void staleReadChecksRevisionBeforeReadingProtectedMetadata() {
        UUID run = run();
        timeline.append(scope.conversationId(), run, "new requirement canary", Set.of(second), FUTURE);
        List<String> observed = new ArrayList<>();
        ConversationTimeline measured = pausedTimeline(sql -> {
            observed.add(sql);
            return false;
        }, new CountDownLatch(0), new CountDownLatch(0));
        assertThat(measured.read(scope.conversationId(), 1, Optional.empty(), 8)).isEmpty();
        assertThat(observed.stream().filter(sql -> sql.contains("FROM f07_proof.conversation")))
                .hasSize(1)
                .allSatisfy(sql -> assertThat(sql).doesNotContain("title", "next_ordinal", "last_run_uuid"));
        assertThat(observed).noneSatisfy(sql -> assertThat(sql).contains("FROM f07_proof.timeline_event"));
    }

    @Test
    void cancellationWinsActualBlockedCompletionWithoutStateResurrection() throws Exception {
        UUID run = run();
        CountDownLatch locked = new CountDownLatch(1);
        CountDownLatch release = new CountDownLatch(1);
        AtomicInteger leaderPid = new AtomicInteger();
        AtomicInteger waiterPid = new AtomicInteger();
        ConversationTimeline leader = pausedTimeline(
                sql -> sql.contains("FROM f07_proof.conversation") && sql.endsWith("FOR UPDATE"), locked, release,
                leaderPid);
        ConversationTimeline follower = observedTimeline(waiterPid);
        try (var pool = Executors.newFixedThreadPool(2)) {
            var cancel = pool.submit(() -> leader.cancel(scope, run, "cancel-race", BODY));
            assertThat(locked.await(3, TimeUnit.SECONDS)).isTrue();
            var complete = pool.submit(() -> follower.complete(run));
            try {
                awaitDatabaseWaiter(waiterPid, leaderPid);
                assertThat(complete.isDone()).isFalse();
            } finally {
                release.countDown();
            }
            assertThat(cancel.get(5, TimeUnit.SECONDS).orElseThrow().state())
                    .isEqualTo(ConversationTimeline.RunState.CANCELLED);
            assertThat(complete.get(5, TimeUnit.SECONDS).state()).isEqualTo(ConversationTimeline.RunState.CANCELLED);
        } finally {
            release.countDown();
        }
    }

    @Test
    void authorizedExpiredUnknownAndForeignCursorsCannotExposeHistory() {
        UUID conversationId = scope.conversationId();
        Optional<UUID> unknownCursor = Optional.of(UUID.randomUUID());
        UUID run = run();
        var expired = timeline.append(conversationId, run, "expired cursor canary", Set.of(first), Instant.EPOCH);
        assertThatThrownBy(() -> fixture.read(ACTOR, conversationId, Optional.of(expired.cursor()), 8))
                .isInstanceOf(ConversationTimeline.CursorExpired.class)
                .hasMessage("Cursor unavailable");
        assertThatThrownBy(() -> fixture.read(ACTOR, conversationId, unknownCursor, 8))
                .isInstanceOf(ConversationTimeline.CursorExpired.class)
                .hasMessage("Cursor unavailable");
        UUID foreign = UUID.randomUUID();
        jdbc
                .update("INSERT INTO f07_proof.conversation VALUES (?,?,?,1,0,?,NULL)", foreign, ACTOR,
                        scope.raProfileId(), "foreign protected title");
        jdbc.update("INSERT INTO f07_proof.retained_certificate VALUES (?,?)", foreign, first);
        var foreignScope = timeline.scope(ACTOR, foreign);
        UUID foreignRun = timeline
                .command(foreignScope, ConversationTimeline.CommandKind.START, "foreign", BODY)
                .orElseThrow()
                .runId();
        var event = timeline.append(foreign, foreignRun, "foreign cursor canary", Set.of(first), FUTURE);
        assertThatThrownBy(() -> fixture.read(ACTOR, conversationId, Optional.of(event.cursor()), 8))
                .isInstanceOf(ConversationTimeline.CursorExpired.class)
                .hasMessage("Cursor unavailable");
        assertThat(count("command_record")).isEqualTo(2);
    }

    @Test
    void commandEntryAndHistoryBoundsRejectWithoutPartialMutation() {
        UUID conversationId = scope.conversationId();
        Set<UUID> secondRequirement = Set.of(second);
        String oversizeKey = "x".repeat(129);
        byte[] oversizeBody = new byte[4097];
        String oversizeValue = "é".repeat(15001);
        assertThatThrownBy(() -> timeline.command(scope, ConversationTimeline.CommandKind.START, oversizeKey, BODY))
                .isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> timeline.command(scope, ConversationTimeline.CommandKind.START, "body", oversizeBody))
                .isInstanceOf(IllegalArgumentException.class);
        assertThat(count("command_record")).isZero();
        UUID run = run();
        assertThatThrownBy(() -> timeline.append(conversationId, run, oversizeValue, secondRequirement, FUTURE))
                .isInstanceOf(IllegalArgumentException.class);
        assertThat(count("timeline_event")).isZero();
        assertThat(count("retained_certificate")).isEqualTo(1);
        for (int i = 0; i < 64; i++) {
            timeline.append(conversationId, run, "bounded canary", Set.of(first), FUTURE);
        }
        assertThatThrownBy(() -> timeline.append(conversationId, run, "overflow", secondRequirement, FUTURE))
                .isInstanceOf(IllegalStateException.class);
        assertThat(count("timeline_event")).isEqualTo(64);
        assertThat(count("retained_certificate")).isEqualTo(1);
        assertThat(timeline.read(conversationId, 1, Optional.empty(), 8).orElseThrow().events()).hasSize(8);
    }

    @Test
    void emptyScopeAndContinuouslyChangingRevisionDenyWithoutMetadata() {
        UUID conversationId = scope.conversationId();
        Optional<UUID> noCursor = Optional.empty();
        AtomicInteger attempts = new AtomicInteger();
        fixture.afterAuthorization(() -> {
            attempts.incrementAndGet();
            jdbc
                    .update("UPDATE f07_proof.conversation SET scope_revision=scope_revision+1 WHERE uuid=?",
                            conversationId);
        });
        assertThatThrownBy(() -> fixture.read(ACTOR, conversationId, noCursor, 8))
                .isInstanceOf(AccessDeniedException.class);
        assertThat(attempts).hasValue(3);
        jdbc.update("DELETE FROM f07_proof.retained_certificate WHERE conversation_uuid=?", conversationId);
        AUTHORITY.exchanges.clear();
        assertThatThrownBy(() -> fixture.read(ACTOR, conversationId, noCursor, 8))
                .isInstanceOf(AccessDeniedException.class);
        assertThat(AUTHORITY.exchanges).isEmpty();
    }

    @Test
    void cursorLookupNeverQueriesForeignConversationExistence() {
        UUID conversationId = scope.conversationId();
        Optional<UUID> unknownCursor = Optional.of(UUID.randomUUID());
        UUID run = run();
        var owned = timeline.append(conversationId, run, "owned cursor canary", Set.of(first), FUTURE);
        List<String> observed = new ArrayList<>();
        ConversationTimeline measured = pausedTimeline(sql -> {
            observed.add(sql);
            return false;
        }, new CountDownLatch(0), new CountDownLatch(0));
        var secured = new ConversationStreamFixture(measured, authorization);
        assertThat(secured.read(ACTOR, conversationId, Optional.of(owned.cursor()), 8).events()).isEmpty();
        var cursorQueries = observed.stream().filter(sql -> sql.contains("cursor_uuid=?")).toList();
        assertThat(cursorQueries)
                .hasSize(1)
                .allSatisfy(sql -> assertThat(sql)
                        .contains("WHERE conversation_uuid=? AND cursor_uuid=?")
                        .doesNotContain("SELECT conversation_uuid"));
        observed.clear();
        assertThatThrownBy(() -> secured.read(OTHER, conversationId, unknownCursor, 8))
                .isInstanceOf(AccessDeniedException.class);
        assertThat(observed).noneSatisfy(sql -> assertThat(sql).contains("FROM f07_proof.timeline_event"));
    }

    @Test
    void eventSqlFailureRollsBackAlreadyWrittenScopeUnionAndOrdinal() {
        UUID conversationId = scope.conversationId();
        Set<UUID> secondRequirement = Set.of(second);
        String nulValue = String.valueOf((char) 0);
        UUID run = run();
        AtomicBoolean writtenBeforeFailure = new AtomicBoolean();
        ConversationTimeline measured = pausedTimeline(sql -> {
            if (sql.startsWith("UPDATE f07_proof.conversation SET next_ordinal")) {
                assertThat(jdbc
                        .queryForObject("SELECT scope_revision FROM f07_proof.conversation WHERE uuid=?", Long.class,
                                conversationId))
                        .isEqualTo(2);
                assertThat(jdbc
                        .queryForObject("SELECT next_ordinal FROM f07_proof.conversation WHERE uuid=?", Long.class,
                                conversationId))
                        .isEqualTo(1);
                assertThat(count("retained_certificate")).isEqualTo(2);
                writtenBeforeFailure.set(true);
            }
            return false;
        }, new CountDownLatch(0), new CountDownLatch(0));
        assertThatThrownBy(() -> measured.append(conversationId, run, nulValue, secondRequirement, FUTURE))
                .isInstanceOf(DataAccessException.class);
        assertThat(writtenBeforeFailure).isTrue();
        assertThat(count("timeline_event")).isZero();
        assertThat(count("retained_certificate")).isEqualTo(1);
        assertThat(timeline.scope(ACTOR, conversationId).revision()).isEqualTo(1);
        assertThat(jdbc
                .queryForObject("SELECT next_ordinal FROM f07_proof.conversation WHERE uuid=?", Long.class,
                        conversationId))
                .isZero();
        assertThat(jdbc.queryForObject("SELECT state FROM f07_proof.run_record WHERE uuid=?", String.class, run))
                .isEqualTo("QUEUED");
        var committed = timeline.append(conversationId, run, "healthy after rollback", secondRequirement, FUTURE);
        assertThat(committed.ordinal()).isEqualTo(1);
        assertThat(timeline.scope(ACTOR, conversationId).revision()).isEqualTo(2);
        assertThat(count("retained_certificate")).isEqualTo(2);
    }

    @Test
    void authorizedReaderHoldsRevisionStableWhileProducerWaitsToCommit() throws Exception {
        UUID run = run();
        CountDownLatch factsRead = new CountDownLatch(1);
        CountDownLatch release = new CountDownLatch(1);
        AtomicInteger readerPid = new AtomicInteger();
        AtomicInteger writerPid = new AtomicInteger();
        ConversationTimeline reader = pausedTimeline(sql -> sql.contains("FROM f07_proof.conversation"), factsRead,
                release, readerPid);
        ConversationTimeline writer = observedTimeline(writerPid);
        authorization.require(ACTOR, scope);
        try (var pool = Executors.newFixedThreadPool(2)) {
            var batch = pool.submit(() -> reader.read(scope.conversationId(), 1, Optional.empty(), 8).orElseThrow());
            assertThat(factsRead.await(3, TimeUnit.SECONDS)).isTrue();
            var producer = pool.submit(() -> {
                authorization
                        .require(ACTOR, new ConversationTimeline.Scope(scope.conversationId(), ACTOR,
                                scope.raProfileId(), 1, Set.of(second)));
                return writer.append(scope.conversationId(), run, "B after reader commits", Set.of(second), FUTURE);
            });
            try {
                awaitDatabaseWaiter(writerPid, readerPid);
                assertThat(producer.isDone()).isFalse();
            } finally {
                release.countDown();
            }
            var old = batch.get(5, TimeUnit.SECONDS);
            assertThat(old.scope().revision()).isEqualTo(1);
            assertThat(old.scope().certificates()).containsExactly(first);
            assertThat(old.events()).isEmpty();
            assertThat(old.count()).isZero();
            assertThat(producer.get(5, TimeUnit.SECONDS).ordinal()).isEqualTo(1);
            var fresh = fixture.read(ACTOR, scope.conversationId(), Optional.empty(), 8);
            assertThat(fresh.scope().revision()).isEqualTo(2);
            assertThat(fresh.events())
                    .extracting(ConversationTimeline.Event::value)
                    .containsExactly("B after reader commits");
        } finally {
            release.countDown();
        }
    }

    private List<Boolean> secondCertificateVotes() {
        return AUTHORITY.exchanges
                .stream()
                .filter(e -> e.path().equals("/v1/data/method")
                        && e.request().at("/input/requestedResource/name").asText().equals("certificates")
                        && e.request().at("/input/requestedResource/uuids/0").asText().equals(second.toString()))
                .map(e -> e.response().at("/result/authorized").asBoolean())
                .toList();
    }

    private UUID run() {
        return timeline.command(scope, ConversationTimeline.CommandKind.START, "start", BODY).orElseThrow().runId();
    }

    private long count(String table) {
        return jdbc.queryForObject("SELECT count(*) FROM f07_proof." + table, Long.class);
    }

    private UUID certificate(RaProfile profile) {
        X509CertificateEntity c = new X509CertificateEntity();
        c.setCommonName("synthetic-f07");
        c.setSubjectDn("CN=synthetic-f07");
        c.setIssuerDn("CN=synthetic issuer");
        c.setSerialNumber(UUID.randomUUID().toString());
        c.setState(CertificateState.ISSUED);
        c.setValidationStatus(CertificateValidationStatus.VALID);
        c.setRaProfileUuid(profile.getUuid());
        return certificates.saveAndFlush(c).getUuid();
    }

    private void allow(Set<UUID> allowed) throws Exception {
        AUTHORITY.principal = JSON
                .writeValueAsString(Map
                        .of("user", Map.of("uuid", ACTOR.toString(), "username", "synthetic-f07", "enabled", true),
                                "roles", List.of(), "permissions",
                                Map
                                        .of("allowAllResources", false, "resources", List
                                                .of(Map
                                                        .of("name", "certificates", "allowAllActions", false, "actions",
                                                                List.of(), "objects",
                                                                allowed
                                                                        .stream()
                                                                        .map(id -> Map
                                                                                .of("uuid", id.toString(), "allow",
                                                                                        List.of("detail"), "deny",
                                                                                        List.of()))
                                                                        .toList()),
                                                        Map
                                                                .of("name", "raProfiles", "allowAllActions", false,
                                                                        "actions", List.of(), "objects",
                                                                        List
                                                                                .of(Map
                                                                                        .of("uuid",
                                                                                                scope
                                                                                                        .raProfileId()
                                                                                                        .toString(),
                                                                                                "allow",
                                                                                                List.of("members"),
                                                                                                "deny", List.of()))),
                                                        Map
                                                                .of("name", "groups", "allowAllActions", false,
                                                                        "actions", List.of(), "objects", List.of())))));
    }

    private ConversationTimeline observedTimeline(AtomicInteger pid) {
        return pausedTimeline(sql -> false, new CountDownLatch(0), new CountDownLatch(0), pid);
    }

    private ConversationTimeline pausedTimeline(Predicate<String> pause, CountDownLatch entered,
            CountDownLatch release) {
        return pausedTimeline(pause, entered, release, new AtomicInteger());
    }

    private ConversationTimeline pausedTimeline(Predicate<String> pause, CountDownLatch entered, CountDownLatch release,
            AtomicInteger backendPid) {
        AtomicBoolean firstCall = new AtomicBoolean(true);
        JdbcOperations observed = (JdbcOperations) Proxy
                .newProxyInstance(JdbcOperations.class.getClassLoader(), new Class<?>[]{JdbcOperations.class},
                        (proxy, method, args) -> {
                            try {
                                if (backendPid.get() == 0) {
                                    backendPid
                                            .compareAndSet(0,
                                                    jdbc.queryForObject("SELECT pg_backend_pid()", Integer.class));
                                }
                                Object result = method.invoke(jdbc, args);
                                if (args != null && args.length > 0 && args[0] instanceof String sql && pause.test(sql)
                                        && firstCall.compareAndSet(true, false)) {
                                    entered.countDown();
                                    await(release);
                                }
                                return result;
                            } catch (InvocationTargetException failure) {
                                throw failure.getCause();
                            }
                        });
        return new ConversationTimeline(observed, transactions);
    }

    private void awaitDatabaseWaiter(AtomicInteger waiter, AtomicInteger blocker) {
        org.awaitility.Awaitility
                .await()
                .alias("exact owned PostgreSQL waiter/blocker pair")
                .pollInterval(java.time.Duration.ofMillis(10))
                .atMost(java.time.Duration.ofSeconds(3))
                .until(() -> waiter.get() > 0 && blocker.get() > 0 && jdbc
                        .queryForObject(
                                "SELECT count(*) FROM pg_stat_activity WHERE pid=? AND datname=current_database() "
                                        + "AND wait_event_type='Lock' AND ?=ANY(pg_blocking_pids(pid))",
                                Long.class, waiter.get(), blocker.get()) == 1);
    }

    private static void await(CountDownLatch latch) {
        try {
            if (!latch.await(5, TimeUnit.SECONDS)) {
                throw new AssertionError("Fixture barrier timed out");
            }
        } catch (InterruptedException failure) {
            Thread.currentThread().interrupt();
            throw new AssertionError("Fixture barrier interrupted");
        }
    }
}
