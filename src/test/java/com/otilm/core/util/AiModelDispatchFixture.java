package com.otilm.core.util;

import com.otilm.ai.runtime.protocol.ManagementAction;
import com.otilm.core.model.ai.AiModelDispatchState.ConnectionVersion;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.sql.Connection;
import java.time.Instant;
import java.util.HexFormat;
import java.util.List;
import java.util.UUID;
import javax.sql.DataSource;
import org.springframework.core.io.ClassPathResource;

/** Private nonce-database fixture facts only. No actual modelUSE, native gateway or approved credential grant. */
public final class AiModelDispatchFixture {
    private static final List<String> TABLES = List
            .of("ai_model_run_intent", "ai_model_management_intent", "ai_model_run_budget",
                    "ai_model_management_session", "ai_model_connection");
    private static final String MIGRATION = "db/migration/V202611051201__ai_model_dispatch.sql";

    private AiModelDispatchFixture() {
    }

    public static void drop(DataSource source) throws Exception {
        try (var connection = source.getConnection(); var statement = connection.createStatement()) {
            statement
                    .execute(
                            "DROP TABLE IF EXISTS ai_model_management_outcome, ai_model_management_gateway_assignment");
            statement.execute("DROP FUNCTION IF EXISTS ai_model_management_gateway_immutable_guard()");
            statement
                    .execute(
                            "DROP TABLE IF EXISTS ai_management_gateway_registration, ai_management_gateway_deployment");
            statement.execute("DROP TABLE IF EXISTS ai_model_run_outcome, ai_model_run_gateway_assignment");
            statement.execute("DROP FUNCTION IF EXISTS ai_model_run_gateway_immutable_guard()");
            statement.execute("DROP TABLE IF EXISTS " + String.join(", ", TABLES));
            statement.execute("DROP FUNCTION IF EXISTS ai_model_connection_revision_guard()");
        }
    }

    public static void install(DataSource source) throws Exception {
        try (var connection = source.getConnection(); var statement = connection.createStatement()) {
            statement
                    .execute(new String(new ClassPathResource(MIGRATION).getContentAsByteArray(),
                            StandardCharsets.UTF_8));
        }
    }

    public static ConnectionVersion approvedModel(DataSource source) throws Exception {
        UUID id = UUID.randomUUID();
        try (var connection = source.getConnection(); var statement = connection.prepareStatement("""
                INSERT INTO ai_model_connection
                    (uuid, revision, destination_revision, authentication_revision, approved_revision,
                        approved_destination_revision, approved_authentication_revision, enabled,
                        origin, credential_reference, model_identifier)
                VALUES (?, 1, 1, 1, 1, 1, 1, TRUE, 'https://provider.invalid:8443', 'ilm-f04-provider-v1', 'lab')
                """)) {
            statement.setObject(1, id);
            requireOne(statement.executeUpdate());
        }
        return new ConnectionVersion(id, 1, 1, 1, "lab");
    }

    public static void runBudget(DataSource source, UUID run, ConnectionVersion model, long calls, long tokens)
            throws Exception {
        try (var connection = source.getConnection();
                var statement = connection
                        .prepareStatement(
                                """
                                        INSERT INTO ai_model_run_budget (run_uuid, connection_uuid, configuration_revision, destination_revision,
                                            authentication_revision, max_calls, max_tokens, reserved_calls, reserved_tokens)
                                        VALUES (?, ?, ?, ?, ?, ?, ?, 0, 0)
                                        """)) {
            statement.setObject(1, run);
            statement.setObject(2, model.id());
            statement.setLong(3, model.configuration());
            statement.setLong(4, model.destination());
            statement.setLong(5, model.authentication());
            statement.setLong(6, calls);
            statement.setLong(7, tokens);
            requireOne(statement.executeUpdate());
        }
    }

    public static void managementSession(DataSource source, UUID actor, UUID session, ConnectionVersion model,
            ManagementAction action, Instant expires) throws Exception {
        try (var connection = source.getConnection(); var statement = connection.prepareStatement("""
                INSERT INTO ai_model_management_session
                    (session_uuid, actor_uuid, connection_uuid, configuration_revision, destination_revision,
                        authentication_revision, action, enabled, expires_at, max_calls, max_tokens,
                        reserved_calls, reserved_tokens)
                VALUES (?, ?, ?, ?, ?, ?, ?, TRUE, ?, 3, 128, 0, 0)
                """)) {
            statement.setObject(1, session);
            statement.setObject(2, actor);
            statement.setObject(3, model.id());
            statement.setLong(4, model.configuration());
            statement.setLong(5, model.destination());
            statement.setLong(6, model.authentication());
            statement.setString(7, action.name());
            statement.setTimestamp(8, java.sql.Timestamp.from(expires));
            requireOne(statement.executeUpdate());
        }
    }

    public static void clearOnlyDestinationApproval(DataSource source, UUID id) throws Exception {
        try (var connection = source.getConnection();
                var statement = connection
                        .prepareStatement(
                                "UPDATE ai_model_connection SET approved_destination_revision = NULL WHERE uuid = ?")) {
            statement.setObject(1, id);
            requireOne(statement.executeUpdate());
        }
    }

    public static void reviseConnection(DataSource source, UUID id) throws Exception {
        try (var connection = source.getConnection(); var statement = connection.prepareStatement("""
                UPDATE ai_model_connection SET revision = revision + 1, approved_revision = NULL,
                    approved_destination_revision = NULL, approved_authentication_revision = NULL WHERE uuid = ?
                """)) {
            statement.setObject(1, id);
            requireOne(statement.executeUpdate());
        }
    }

    public static boolean approved(DataSource source, UUID id) throws Exception {
        try (var connection = source.getConnection(); var statement = connection.prepareStatement("""
                SELECT approved_revision = revision AND approved_destination_revision = destination_revision
                    AND approved_authentication_revision = authentication_revision
                FROM ai_model_connection WHERE uuid = ?
                """)) {
            statement.setObject(1, id);
            try (var rows = statement.executeQuery()) {
                requireRow(rows.next());
                return rows.getBoolean(1);
            }
        }
    }

    public static long count(DataSource source, String table) throws Exception {
        if (!TABLES.contains(table) && !table.equals("ai_runtime_run")) {
            throw new IllegalArgumentException("Unknown fixture table");
        }
        try (var connection = source.getConnection();
                var statement = connection.createStatement();
                var rows = statement.executeQuery("SELECT count(*) FROM " + table)) {
            requireRow(rows.next());
            return rows.getLong(1);
        }
    }

    public static long reservedCalls(DataSource source, UUID run) throws Exception {
        try (var connection = source.getConnection(); var statement = connection.prepareStatement("""
                SELECT reserved_calls FROM ai_model_run_budget WHERE run_uuid = ?
                """)) {
            statement.setObject(1, run);
            try (var rows = statement.executeQuery()) {
                requireRow(rows.next());
                return rows.getLong(1);
            }
        }
    }

    public static boolean consumed(DataSource source, UUID intent, boolean management) throws Exception {
        String table = management ? "ai_model_management_intent" : "ai_model_run_intent";
        try (var connection = source.getConnection();
                var statement = connection
                        .prepareStatement(
                                "SELECT state = 'CONSUMED' AND consumed_at IS NOT NULL AND gateway_correlation IS NOT NULL FROM "
                                        + table + " WHERE uuid = ?")) {
            statement.setObject(1, intent);
            try (var rows = statement.executeQuery()) {
                requireRow(rows.next());
                return rows.getBoolean(1);
            }
        }
    }

    public static String fingerprint(DataSource source) throws Exception {
        try (Connection connection = source.getConnection()) {
            return fingerprint(connection);
        }
    }

    public static String fingerprint(Connection connection) throws Exception {
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        try (var statement = connection.createStatement()) {
            for (String table : TABLES) {
                digest.update(table.getBytes(StandardCharsets.UTF_8));
                try (var rows = statement
                        .executeQuery("SELECT row_to_json(observed)::text FROM " + table + " observed ORDER BY 1")) {
                    while (rows.next()) {
                        digest.update(rows.getString(1).getBytes(StandardCharsets.UTF_8));
                        digest.update((byte) '\n');
                    }
                }
            }
        }
        return HexFormat.of().formatHex(digest.digest());
    }

    public static com.otilm.core.model.ai.AiModelDispatchState.ExactPayload payload(int tokens, String text) {
        String json = "{\"model\":\"lab\",\"messages\":[{\"role\":\"user\",\"content\":\"" + text
                + "\"}],\"max_tokens\":" + tokens + ",\"stream\":false}";
        return new com.otilm.core.model.ai.AiModelDispatchState.ExactPayload(json.getBytes(StandardCharsets.UTF_8));
    }

    public static void mutateWithoutRevision(DataSource source, UUID id, boolean credential) throws Exception {
        execute(source,
                credential
                        ? "UPDATE ai_model_connection SET credential_reference='changed-ref' WHERE uuid=?"
                        : "UPDATE ai_model_connection SET origin='https://changed.invalid' WHERE uuid=?",
                id);
    }

    public static void decreaseRevision(DataSource source, UUID id) throws Exception {
        execute(source, "UPDATE ai_model_connection SET revision=revision-1, approved_revision=NULL, "
                + "approved_destination_revision=NULL, approved_authentication_revision=NULL WHERE uuid=?", id);
    }

    public static ConnectionVersion advance(DataSource source, UUID id, String axis, boolean reapprove)
            throws Exception {
        String extra = switch (axis) {
            case "configuration" -> "";
            case "destination" -> ", destination_revision=destination_revision+1";
            case "authentication" -> ", authentication_revision=authentication_revision+1";
            default -> throw new IllegalArgumentException("Unknown fixture axis");
        };
        execute(source, "UPDATE ai_model_connection SET revision=revision+1" + extra + ", approved_revision=NULL, "
                + "approved_destination_revision=NULL, approved_authentication_revision=NULL WHERE uuid=?", id);
        if (reapprove) {
            execute(source,
                    "UPDATE ai_model_connection SET approved_revision=revision, "
                            + "approved_destination_revision=destination_revision, "
                            + "approved_authentication_revision=authentication_revision WHERE uuid=?",
                    id);
        }
        try (var connection = source.getConnection();
                var statement = connection
                        .prepareStatement(
                                "SELECT revision,destination_revision,authentication_revision,model_identifier FROM ai_model_connection WHERE uuid=?")) {
            statement.setObject(1, id);
            try (var rows = statement.executeQuery()) {
                requireRow(rows.next());
                return new ConnectionVersion(id, rows.getLong(1), rows.getLong(2), rows.getLong(3), rows.getString(4));
            }
        }
    }

    public static void changeBoundValueWithRevisions(DataSource source, UUID id, boolean credential) throws Exception {
        execute(source, credential
                ? "UPDATE ai_model_connection SET revision=revision+1, authentication_revision=authentication_revision+1, "
                        + "credential_reference='changed-ref' WHERE uuid=?"
                : "UPDATE ai_model_connection SET revision=revision+1, destination_revision=destination_revision+1, "
                        + "origin='https://changed.invalid' WHERE uuid=?",
                id);
    }

    public static boolean approvalsCleared(DataSource source, UUID id) throws Exception {
        try (var connection = source.getConnection();
                var statement = connection
                        .prepareStatement("SELECT approved_revision IS NULL AND approved_destination_revision IS NULL "
                                + "AND approved_authentication_revision IS NULL FROM ai_model_connection WHERE uuid=?")) {
            statement.setObject(1, id);
            try (var rows = statement.executeQuery()) {
                requireRow(rows.next());
                return rows.getBoolean(1);
            }
        }
    }

    public static void insertOrigin(DataSource source, String origin) throws Exception {
        try (var connection = source.getConnection();
                var statement = connection
                        .prepareStatement(
                                "INSERT INTO ai_model_connection(uuid,revision,destination_revision,authentication_revision,origin,"
                                        + "credential_reference,model_identifier) VALUES(?,1,1,1,?,'fixture-ref','lab')")) {
            statement.setObject(1, UUID.randomUUID());
            statement.setString(2, origin);
            requireOne(statement.executeUpdate());
        }
    }

    public static void clearApproval(DataSource source, UUID id, String axis) throws Exception {
        String column = switch (axis) {
            case "configuration" -> "approved_revision";
            case "destination" -> "approved_destination_revision";
            case "authentication" -> "approved_authentication_revision";
            default -> throw new IllegalArgumentException("Unknown fixture axis");
        };
        execute(source, "UPDATE ai_model_connection SET " + column + "=NULL WHERE uuid=?", id);
    }

    public static void updateRunPolicy(DataSource source, UUID run, ConnectionVersion model) throws Exception {
        try (var connection = source.getConnection();
                var statement = connection
                        .prepareStatement(
                                "UPDATE ai_model_run_budget SET configuration_revision=?,destination_revision=?,authentication_revision=? "
                                        + "WHERE run_uuid=?")) {
            statement.setLong(1, model.configuration());
            statement.setLong(2, model.destination());
            statement.setLong(3, model.authentication());
            statement.setObject(4, run);
            requireOne(statement.executeUpdate());
        }
    }

    public static void limits(DataSource source, UUID id, boolean management, long calls, long tokens)
            throws Exception {
        String table = management ? "ai_model_management_session" : "ai_model_run_budget";
        String column = management ? "session_uuid" : "run_uuid";
        try (var connection = source.getConnection();
                var statement = connection
                        .prepareStatement("UPDATE " + table + " SET max_calls=?,max_tokens=? WHERE " + column + "=?")) {
            statement.setLong(1, calls);
            statement.setLong(2, tokens);
            statement.setObject(3, id);
            requireOne(statement.executeUpdate());
        }
    }

    public static long reservedTokens(DataSource source, UUID id, boolean management) throws Exception {
        String table = management ? "ai_model_management_session" : "ai_model_run_budget";
        String column = management ? "session_uuid" : "run_uuid";
        try (var connection = source.getConnection();
                var statement = connection
                        .prepareStatement("SELECT reserved_tokens FROM " + table + " WHERE " + column + "=?")) {
            statement.setObject(1, id);
            try (var rows = statement.executeQuery()) {
                requireRow(rows.next());
                return rows.getLong(1);
            }
        }
    }

    private static void execute(DataSource source, String sql, UUID id) throws Exception {
        try (var connection = source.getConnection(); var statement = connection.prepareStatement(sql)) {
            statement.setObject(1, id);
            requireOne(statement.executeUpdate());
        }
    }

    private static void requireOne(int count) {
        if (count != 1) {
            throw new AssertionError("Unexpected fixture row count");
        }
    }

    private static void requireRow(boolean present) {
        if (!present) {
            throw new AssertionError("Missing fixture row");
        }
    }
}
