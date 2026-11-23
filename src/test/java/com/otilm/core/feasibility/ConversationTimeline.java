package com.otilm.core.feasibility;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.time.Instant;
import java.util.HexFormat;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;
import java.util.function.Supplier;
import org.springframework.jdbc.core.JdbcOperations;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.support.TransactionSynchronizationManager;
import org.springframework.transaction.support.TransactionTemplate;

/** Local fixture facts; constructing a scope does not authorize a read or command. */
public final class ConversationTimeline {
    public enum RunState {
        QUEUED,
        RUNNING,
        COMPLETE,
        CANCELLED
    }

    public enum CommandKind {
        START,
        FOLLOW_UP,
        CANCEL
    }

    public record Scope(UUID conversationId, UUID owner, UUID raProfileId, long revision, Set<UUID> certificates) {
        public Scope {
            certificates = Set.copyOf(certificates);
        }
    }

    public record Event(UUID cursor, long ordinal, UUID runId, String value, Instant cursorExpiresAt) {
    }

    public record RunResult(UUID runId, RunState state, boolean replay) {
    }

    public record Batch(Scope scope, Optional<RunResult> run, List<Event> events, String title, long count) {
        public Batch {
            events = List.copyOf(events);
        }
    }

    public static final class CursorExpired extends RuntimeException {
        public CursorExpired() {
            super("Cursor unavailable");
        }
    }

    public static final class CommandConflict extends IllegalStateException {
        public CommandConflict() {
            super("Command conflict");
        }
    }

    private record Conversation(UUID id, UUID owner, UUID profile, long revision, long ordinal, String title,
            UUID run) {
    }

    private final JdbcOperations jdbc;
    private final TransactionTemplate transaction;

    public ConversationTimeline(JdbcOperations jdbc, PlatformTransactionManager transactions) {
        this.jdbc = jdbc;
        transaction = new TransactionTemplate(transactions);
        transaction.setTimeout(5);
    }

    public Scope scope(UUID actor, UUID conversation) {
        return local(() -> {
            Conversation row = scopeFacts(conversation, "FOR SHARE");
            if (!row.owner().equals(actor)) {
                throw denied();
            }
            return scope(row);
        });
    }

    public Optional<RunResult> command(Scope expected, CommandKind kind, String key, byte[] body) {
        if (kind == null || kind == CommandKind.CANCEL) {
            throw new IllegalArgumentException("Invalid command");
        }
        String digest = digest(key, body);
        return local(() -> {
            Conversation row = scopeFacts(expected.conversationId(), "FOR UPDATE");
            if (!matches(row, expected)) {
                return Optional.empty();
            }
            Optional<RunResult> replay = replay(expected, kind, key, digest, null);
            if (replay.isPresent()) {
                return replay;
            }
            if (jdbc
                    .queryForObject("SELECT count(*) FROM f07_proof.run_record WHERE conversation_uuid=? "
                            + "AND state IN ('QUEUED','RUNNING')", Long.class, row.id()) != 0) {
                throw conflict();
            }
            UUID run = UUID.randomUUID();
            jdbc.update("INSERT INTO f07_proof.run_record VALUES (?,?,'QUEUED')", run, row.id());
            remember(expected, kind, key, digest, null, run);
            jdbc.update("UPDATE f07_proof.conversation SET last_run_uuid=? WHERE uuid=?", run, row.id());
            return Optional.of(new RunResult(run, RunState.QUEUED, false));
        });
    }

    public Optional<RunResult> cancel(Scope expected, UUID run, String key, byte[] body) {
        String digest = digest(key, body);
        return local(() -> {
            Conversation row = scopeFacts(expected.conversationId(), "FOR UPDATE");
            if (!matches(row, expected)) {
                return Optional.empty();
            }
            Optional<RunResult> replay = replay(expected, CommandKind.CANCEL, key, digest, run);
            if (replay.isPresent()) {
                return replay;
            }
            run(row.id(), run, false);
            jdbc
                    .update("UPDATE f07_proof.run_record SET state='CANCELLED' WHERE uuid=? AND conversation_uuid=? "
                            + "AND state IN ('QUEUED','RUNNING')", run, row.id());
            remember(expected, CommandKind.CANCEL, key, digest, run, run);
            return Optional.of(run(row.id(), run, false));
        });
    }

    public Event append(UUID conversation, UUID run, String value, Set<UUID> requirements, Instant cursorExpiresAt) {
        if (value == null || value.getBytes(StandardCharsets.UTF_8).length > 30000 || requirements == null
                || requirements.isEmpty() || requirements.size() > 100 || cursorExpiresAt == null) {
            throw new IllegalArgumentException("Invalid fixture entry");
        }
        Set<UUID> added = Set.copyOf(requirements);
        return local(() -> {
            Conversation row = conversation(conversation, "FOR UPDATE");
            RunState state = run(conversation, run, false).state();
            if (state != RunState.QUEUED && state != RunState.RUNNING || row.ordinal() >= 64) {
                throw conflict();
            }
            Set<UUID> retained = scope(row).certificates();
            long newCount = added.stream().filter(id -> !retained.contains(id)).count();
            if (retained.size() + newCount > 100) {
                throw conflict();
            }
            for (UUID id : added) {
                jdbc
                        .update("INSERT INTO f07_proof.retained_certificate VALUES (?,?) ON CONFLICT DO NOTHING",
                                conversation, id);
            }
            long ordinal = row.ordinal() + 1;
            jdbc
                    .update("UPDATE f07_proof.conversation SET next_ordinal=?,scope_revision=scope_revision+? WHERE uuid=?",
                            ordinal, newCount > 0 ? 1 : 0, conversation);
            UUID cursor = UUID.randomUUID();
            jdbc
                    .update("INSERT INTO f07_proof.timeline_event VALUES (?,?,?,?,?,?)", cursor, conversation, ordinal,
                            run, value, java.sql.Timestamp.from(cursorExpiresAt));
            jdbc.update("UPDATE f07_proof.run_record SET state='RUNNING' WHERE uuid=?", run);
            return new Event(cursor, ordinal, run, value, cursorExpiresAt);
        });
    }

    public RunResult complete(UUID run) {
        return local(() -> {
            List<UUID> conversations = jdbc
                    .query("SELECT conversation_uuid FROM f07_proof.run_record WHERE uuid=?",
                            (rs, index) -> rs.getObject(1, UUID.class), run);
            if (conversations.isEmpty()) {
                throw denied();
            }
            UUID conversation = conversations.getFirst();
            scopeFacts(conversation, "FOR UPDATE");
            jdbc
                    .update("UPDATE f07_proof.run_record SET state='COMPLETE' WHERE uuid=? "
                            + "AND state IN ('QUEUED','RUNNING')", run);
            return run(conversation, run, false);
        });
    }

    public Optional<Batch> read(UUID conversation, long revision, Optional<UUID> cursor, int limit) {
        if (limit < 1 || limit > 8 || cursor == null) {
            throw new IllegalArgumentException("Invalid read bound");
        }
        return local(() -> {
            Conversation facts = scopeFacts(conversation, "FOR SHARE");
            if (facts.revision() != revision) {
                return Optional.empty();
            }
            Conversation row = conversation(conversation, "");
            long after = cursor.map(id -> cursorOrdinal(conversation, id)).orElse(0L);
            List<Event> events = jdbc
                    .query("SELECT cursor_uuid,ordinal,run_uuid,value,cursor_expires_at "
                            + "FROM f07_proof.timeline_event WHERE conversation_uuid=? AND ordinal>? ORDER BY ordinal LIMIT ?",
                            (rs, index) -> new Event(rs.getObject(1, UUID.class), rs.getLong(2),
                                    rs.getObject(3, UUID.class), rs.getString(4), rs.getTimestamp(5).toInstant()),
                            conversation, after, limit);
            Optional<RunResult> run = row.run() == null
                    ? Optional.empty()
                    : Optional.of(run(conversation, row.run(), false));
            return Optional.of(new Batch(scope(row), run, events, row.title(), row.ordinal()));
        });
    }

    private long cursorOrdinal(UUID conversation, UUID cursor) {
        return jdbc
                .query("SELECT ordinal,cursor_expires_at<=clock_timestamp() "
                        + "FROM f07_proof.timeline_event WHERE conversation_uuid=? AND cursor_uuid=?", rs -> {
                            if (!rs.next() || rs.getBoolean(2)) {
                                throw new CursorExpired();
                            }
                            return rs.getLong(1);
                        }, conversation, cursor);
    }

    private Optional<RunResult> replay(Scope scope, CommandKind kind, String key, String digest, UUID target) {
        return jdbc
                .query("SELECT kind,body_digest,target_run_uuid,run_uuid FROM f07_proof.command_record "
                        + "WHERE actor_uuid=? AND conversation_uuid=? AND command_key=?", rs -> {
                            if (!rs.next()) {
                                return Optional.empty();
                            }
                            if (!kind.name().equals(rs.getString(1)) || !digest.equals(rs.getString(2))
                                    || !java.util.Objects.equals(target, rs.getObject(3, UUID.class))) {
                                throw conflict();
                            }
                            return Optional.of(run(scope.conversationId(), rs.getObject(4, UUID.class), true));
                        }, scope.owner(), scope.conversationId(), key);
    }

    private void remember(Scope scope, CommandKind kind, String key, String digest, UUID target, UUID run) {
        jdbc
                .update("INSERT INTO f07_proof.command_record VALUES (?,?,?,?,?,?,?)", scope.owner(),
                        scope.conversationId(), key, kind.name(), digest, target, run);
    }

    private RunResult run(UUID conversation, UUID run, boolean replay) {
        List<RunResult> rows = jdbc
                .query("SELECT state FROM f07_proof.run_record WHERE conversation_uuid=? AND uuid=?",
                        (rs, index) -> new RunResult(run, RunState.valueOf(rs.getString(1)), replay), conversation,
                        run);
        if (rows.isEmpty()) {
            throw denied();
        }
        return rows.getFirst();
    }

    private Conversation scopeFacts(UUID conversation, String lock) {
        List<Conversation> rows = jdbc
                .query("SELECT uuid,owner_uuid,ra_profile_uuid,scope_revision "
                        + "FROM f07_proof.conversation WHERE uuid=? " + lock,
                        (rs, index) -> new Conversation(rs.getObject(1, UUID.class), rs.getObject(2, UUID.class),
                                rs.getObject(3, UUID.class), rs.getLong(4), 0, null, null),
                        conversation);
        if (rows.isEmpty()) {
            throw denied();
        }
        return rows.getFirst();
    }

    private Conversation conversation(UUID conversation, String lock) {
        List<Conversation> rows = jdbc
                .query("SELECT uuid,owner_uuid,ra_profile_uuid,scope_revision,next_ordinal,title,last_run_uuid "
                        + "FROM f07_proof.conversation WHERE uuid=? " + lock, (rs, index) -> row(rs), conversation);
        if (rows.isEmpty()) {
            throw denied();
        }
        return rows.getFirst();
    }

    private static Conversation row(ResultSet rs) throws SQLException {
        return new Conversation(rs.getObject(1, UUID.class), rs.getObject(2, UUID.class), rs.getObject(3, UUID.class),
                rs.getLong(4), rs.getLong(5), rs.getString(6), rs.getObject(7, UUID.class));
    }

    private Scope scope(Conversation row) {
        Set<UUID> certificates = Set
                .copyOf(jdbc
                        .query("SELECT certificate_uuid FROM f07_proof.retained_certificate "
                                + "WHERE conversation_uuid=? LIMIT 101", (rs, index) -> rs.getObject(1, UUID.class),
                                row.id()));
        if (certificates.isEmpty() || certificates.size() > 100) {
            throw denied();
        }
        return new Scope(row.id(), row.owner(), row.profile(), row.revision(), certificates);
    }

    private static boolean matches(Conversation row, Scope scope) {
        return row.revision() == scope.revision() && row.owner().equals(scope.owner())
                && row.profile().equals(scope.raProfileId());
    }

    private <T> T local(Supplier<T> operation) {
        if (TransactionSynchronizationManager.isActualTransactionActive()) {
            throw new IllegalStateException("Ambient transaction unavailable");
        }
        return transaction.execute(status -> {
            jdbc.execute("SET LOCAL lock_timeout='2s'");
            jdbc.execute("SET LOCAL statement_timeout='3s'");
            return operation.get();
        });
    }

    private static String digest(String key, byte[] body) {
        if (key == null || !key.matches("[!-~]{1,128}") || body == null || body.length > 4096) {
            throw new IllegalArgumentException("Invalid command bound");
        }
        try {
            return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(body.clone()));
        } catch (NoSuchAlgorithmException failure) {
            throw new IllegalStateException("Digest unavailable");
        }
    }

    private static CommandConflict conflict() {
        return new CommandConflict();
    }

    private static AccessDeniedException denied() {
        return new AccessDeniedException("Conversation unavailable");
    }
}
