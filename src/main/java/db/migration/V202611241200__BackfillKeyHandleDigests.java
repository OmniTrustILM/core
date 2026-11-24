package db.migration;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectReader;
import com.otilm.api.model.common.attribute.common.MetadataAttribute;
import com.otilm.api.model.core.cryptography.key.KeyState;
import com.otilm.core.model.crypto.RemoteKeyReference.MetadataReference;
import com.otilm.core.serialization.ObjectMapperFactory;
import com.otilm.core.util.DatabaseMigration;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import org.flywaydb.core.api.migration.BaseJavaMigration;
import org.flywaydb.core.api.migration.Context;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Stores the handle digest of each key whose token still holds its private key, so the token's key list recognizes keys
 * created before Core recorded handles. A digest that a key on the same token already holds, or that two keys there
 * would share, stays unset and is logged: the migration cannot tell which key the token holds under that handle.
 */
// Flyway mandates the V<version>__<Description> class-name format, which cannot match Sonar's S101 identifier pattern.
@SuppressWarnings("java:S101")
public class V202611241200__BackfillKeyHandleDigests extends BaseJavaMigration {

    private static final Logger logger = LoggerFactory.getLogger(V202611241200__BackfillKeyHandleDigests.class);

    private static final ObjectReader KEY_META_READER = ObjectMapperFactory
            .jsonColumn()
            .readerFor(new TypeReference<List<MetadataAttribute>>() {
            });

    private static final Set<String> DESTROYED_STATES = Set
            .of(KeyState.DESTROYED.name(), KeyState.DESTROYED_COMPROMISED.name());

    private static final String LOCK_KEYS = "LOCK TABLE cryptographic_key, cryptographic_key_item IN EXCLUSIVE MODE";

    private static final String READ_HELD_DIGESTS = """
            SELECT token_instance_uuid, handle_digest
            FROM cryptographic_key
            WHERE token_instance_uuid IS NOT NULL AND handle_digest IS NOT NULL
            """;

    private static final String READ_PRIVATE_KEY_HANDLES = """
            SELECT k.uuid, k.token_instance_uuid, i.state, i.key_meta
            FROM cryptographic_key k
            JOIN cryptographic_key_item i ON i.key_uuid = k.uuid
            WHERE k.token_instance_uuid IS NOT NULL
              AND k.handle_digest IS NULL
              AND i.type = 'PRIVATE_KEY'
              AND i.key_meta IS NOT NULL
            ORDER BY k.uuid
            """;

    private static final String STORE_DIGEST = "UPDATE cryptographic_key SET handle_digest = ? WHERE uuid = ?";

    @Override
    public Integer getChecksum() {
        return DatabaseMigration.JavaMigrationChecksums.V202611241200__BackfillKeyHandleDigests.getChecksum();
    }

    @Override
    public void migrate(Context context) throws SQLException {
        Connection connection = context.getConnection();
        try (Statement statement = connection.createStatement()) {
            statement.execute(LOCK_KEYS);
        }
        Set<TokenHandle> heldHandles = readHeldHandles(connection);
        Map<TokenHandle, List<UUID>> keysByHandle = readKeysByHandle(connection);
        List<KeyDigest> digests = new ArrayList<>();
        keysByHandle.forEach((handle, keyUuids) -> {
            if (heldHandles.contains(handle) || keyUuids.size() > 1) {
                logger
                        .warn("Keys {} on token instance {} keep no handle digest: another key on the token holds or"
                                + " shares the handle of their private key", keyUuids, handle.tokenInstanceUuid());
            } else {
                digests.add(new KeyDigest(keyUuids.getFirst(), handle.digest()));
            }
        });
        storeDigests(connection, digests);
        logger.info("Key handle digests stored: {} keys", digests.size());
    }

    private static Set<TokenHandle> readHeldHandles(Connection connection) throws SQLException {
        Set<TokenHandle> held = new HashSet<>();
        try (PreparedStatement statement = connection.prepareStatement(READ_HELD_DIGESTS);
                ResultSet rows = statement.executeQuery()) {
            while (rows.next()) {
                held.add(new TokenHandle(rows.getObject("token_instance_uuid", UUID.class),
                        rows.getString("handle_digest")));
            }
        }
        return held;
    }

    /** Groups the keys by the handle of their live private key; a key whose private keys name two handles has none. */
    private static Map<TokenHandle, List<UUID>> readKeysByHandle(Connection connection) throws SQLException {
        Map<UUID, Set<TokenHandle>> handlesByKey = new LinkedHashMap<>();
        try (PreparedStatement statement = connection.prepareStatement(READ_PRIVATE_KEY_HANDLES);
                ResultSet rows = statement.executeQuery()) {
            while (rows.next()) {
                UUID keyUuid = rows.getObject("uuid", UUID.class);
                String digest = DESTROYED_STATES.contains(rows.getString("state"))
                        ? null
                        : digestOf(keyUuid, rows.getString("key_meta"));
                if (digest != null) {
                    handlesByKey
                            .computeIfAbsent(keyUuid, uuid -> new HashSet<>())
                            .add(new TokenHandle(rows.getObject("token_instance_uuid", UUID.class), digest));
                }
            }
        }
        Map<TokenHandle, List<UUID>> keysByHandle = new LinkedHashMap<>();
        handlesByKey.forEach((keyUuid, handles) -> {
            if (handles.size() > 1) {
                logger.warn("Key {} keeps no handle digest: its private keys name {} handles", keyUuid, handles.size());
            } else {
                keysByHandle.computeIfAbsent(handles.iterator().next(), handle -> new ArrayList<>()).add(keyUuid);
            }
        });
        return keysByHandle;
    }

    private static String digestOf(UUID keyUuid, String keyMeta) {
        try {
            return new MetadataReference(KEY_META_READER.readValue(keyMeta)).digest();
        } catch (JsonProcessingException e) {
            logger.warn("Key {} keeps no handle digest: the handle of its private key cannot be read", keyUuid);
            return null;
        }
    }

    private static void storeDigests(Connection connection, List<KeyDigest> digests) throws SQLException {
        try (PreparedStatement statement = connection.prepareStatement(STORE_DIGEST)) {
            for (KeyDigest digest : digests) {
                statement.setString(1, digest.digest());
                statement.setObject(2, digest.keyUuid());
                statement.addBatch();
            }
            statement.executeBatch();
        }
    }

    private record TokenHandle(UUID tokenInstanceUuid, String digest) {
    }

    private record KeyDigest(UUID keyUuid, String digest) {
    }
}
