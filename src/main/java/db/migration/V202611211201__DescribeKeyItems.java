package db.migration;

import com.otilm.api.model.common.enums.cryptography.KeyAlgorithm;
import com.otilm.api.model.common.enums.cryptography.KeyFormat;
import com.otilm.api.model.common.enums.cryptography.KeyType;
import com.otilm.api.model.core.cryptography.key.KeyState;
import com.otilm.core.key.description.DescribedKey;
import com.otilm.core.key.description.KeyDescriber;
import com.otilm.core.key.description.KeyParameters;
import com.otilm.core.key.description.RelatedKeyDescriber;
import com.otilm.core.key.description.RelatedKeyDescriber.KeyHalf;
import com.otilm.core.model.crypto.KeyMaterial;
import com.otilm.core.util.DatabaseMigration;
import java.sql.Array;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.sql.Types;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;
import java.util.stream.Collectors;
import org.flywaydb.core.api.migration.BaseJavaMigration;
import org.flywaydb.core.api.migration.Context;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Describes every stored key item as Core describes new ones. An item whose algorithm, size, format or key data changes
 * loses its compliance result.
 */
// Flyway mandates the V<version>__<Description> class-name format, which cannot match Sonar's S101 identifier pattern.
@SuppressWarnings("java:S101")
public class V202611211201__DescribeKeyItems extends BaseJavaMigration {

    private static final Logger logger = LoggerFactory.getLogger(V202611211201__DescribeKeyItems.class);

    private static final int DEFAULT_PAGE_SIZE = 500;

    private static final UUID BEFORE_FIRST_PAGE = null;

    private static final String KEEPS_ITS_KEY_DATA = null;

    private static final Set<KeyState> DESTROYED_STATES = Set.of(KeyState.DESTROYED, KeyState.DESTROYED_COMPROMISED);

    private static final String ITEM_COLUMNS = "uuid, key_uuid, type, key_algorithm, parameter_set, length, format,"
            + " key_data, state";

    private static final String LOCK_ITEMS = "LOCK TABLE cryptographic_key_item IN EXCLUSIVE MODE";

    private static final String UPDATE_DESCRIPTION = """
            UPDATE cryptographic_key_item
            SET key_algorithm = ?, parameter_set = ?, length = ?,
                compliance_status = CASE WHEN ? THEN 'NOT_CHECKED' ELSE compliance_status END,
                compliance_result = CASE WHEN ? THEN NULL ELSE compliance_result END
            WHERE uuid = ?
            """;

    private static final String STORE_IDENTIFIER = """
            UPDATE cryptographic_key_item
            SET format = ?, key_data = ?, fingerprint = NULL
            WHERE uuid = ?
            """;

    private final int pageSize;

    public V202611211201__DescribeKeyItems() {
        this(DEFAULT_PAGE_SIZE);
    }

    /** Lets a test span several pages with a handful of rows. */
    public V202611211201__DescribeKeyItems(int pageSize) {
        this.pageSize = pageSize;
    }

    @Override
    public Integer getChecksum() {
        return DatabaseMigration.JavaMigrationChecksums.V202611211201__DescribeKeyItems.getChecksum();
    }

    @Override
    public void migrate(Context context) throws SQLException {
        Connection connection = context.getConnection();
        try (Statement statement = connection.createStatement()) {
            statement.execute(LOCK_ITEMS);
        }
        int changed = 0;
        Page page = readPage(connection, BEFORE_FIRST_PAGE);
        while (page.lastScanned() != null) {
            Map<UUID, List<StoredItem>> itemsByKey = readItemsOfKeys(connection, keyUuidsOf(page.readableItems()));
            List<ItemUpdate> updates = page
                    .readableItems()
                    .stream()
                    .map(item -> described(item, itemsByKey.getOrDefault(item.keyUuid(), List.of(item))))
                    .filter(ItemUpdate::changesTheRow)
                    .toList();
            applyUpdates(connection, updates);
            changed += updates.size();
            page = readPage(connection, page.lastScanned());
        }
        logger.info("Key item descriptions updated: {} rows rewritten", changed);
    }

    private Page readPage(Connection connection, UUID after) throws SQLException {
        String query = "SELECT " + ITEM_COLUMNS + " FROM cryptographic_key_item"
                + (after == BEFORE_FIRST_PAGE ? "" : " WHERE uuid > ?") + " ORDER BY uuid LIMIT ?";
        try (PreparedStatement statement = connection.prepareStatement(query)) {
            int parameter = 1;
            if (after != BEFORE_FIRST_PAGE) {
                statement.setObject(parameter++, after);
            }
            statement.setInt(parameter, pageSize);
            List<StoredItem> items = new ArrayList<>();
            UUID last = null;
            try (ResultSet rows = statement.executeQuery()) {
                while (rows.next()) {
                    last = rows.getObject("uuid", UUID.class);
                    readItem(rows).ifPresent(items::add);
                }
            }
            return new Page(items, last);
        }
    }

    private static Map<UUID, List<StoredItem>> readItemsOfKeys(Connection connection, Collection<UUID> keyUuids)
            throws SQLException {
        String query = "SELECT " + ITEM_COLUMNS + " FROM cryptographic_key_item WHERE key_uuid = ANY (?)";
        try (PreparedStatement statement = connection.prepareStatement(query)) {
            Array keys = connection.createArrayOf("uuid", keyUuids.toArray());
            statement.setArray(1, keys);
            return readItems(statement).stream().collect(Collectors.groupingBy(StoredItem::keyUuid));
        }
    }

    private static List<StoredItem> readItems(PreparedStatement statement) throws SQLException {
        List<StoredItem> items = new ArrayList<>();
        try (ResultSet rows = statement.executeQuery()) {
            while (rows.next()) {
                readItem(rows).ifPresent(items::add);
            }
        }
        return items;
    }

    private static Optional<StoredItem> readItem(ResultSet row) throws SQLException {
        UUID uuid = row.getObject("uuid", UUID.class);
        try {
            return Optional.of(new StoredItem(uuid, row.getObject("key_uuid", UUID.class),
                    KeyType.valueOf(row.getString("type")),
                    enumOrNull(KeyAlgorithm.class, row.getString("key_algorithm")), row.getString("parameter_set"),
                    row.getObject("length", Integer.class), enumOrNull(KeyFormat.class, row.getString("format")),
                    row.getString("key_data"), KeyState.valueOf(row.getString("state"))));
        } catch (IllegalArgumentException e) {
            logger.warn("Key item {} keeps its description: it names a type, algorithm, format or state unknown to this"
                    + " release", uuid);
            return Optional.empty();
        }
    }

    private static List<UUID> keyUuidsOf(List<StoredItem> items) {
        return items.stream().map(StoredItem::keyUuid).filter(Objects::nonNull).distinct().toList();
    }

    /** Describes the item among its key's live items, and a destroyed item from its statement alone. */
    static ItemUpdate described(StoredItem item, List<StoredItem> itemsOfKey) {
        if (DESTROYED_STATES.contains(item.state())) {
            return item.updatedTo(asStated(item));
        }
        KeyHalf half = item.half();
        List<KeyHalf> related = itemsOfKey
                .stream()
                .filter(sibling -> !DESTROYED_STATES.contains(sibling.state()))
                .map(StoredItem::half)
                .toList();
        DescribedKey described = RelatedKeyDescriber.describe(half, related);
        return item.identifiedAs(described, storedIdentifier(item, half, related));
    }

    /** A private item stored without key data gets the AlgorithmIdentifier from its public siblings. */
    private static String storedIdentifier(StoredItem item, KeyHalf half, List<KeyHalf> related) {
        if (!heldByTheTokenAlone(item)) {
            return KEEPS_ITS_KEY_DATA;
        }
        return RelatedKeyDescriber
                .agreedByPublicSiblings(half, related)
                .map(KeyParameters::base64Identifier)
                .orElse(KEEPS_ITS_KEY_DATA);
    }

    private static boolean heldByTheTokenAlone(StoredItem item) {
        return item.type() != KeyType.PUBLIC_KEY && item.type() != KeyType.SECRET_KEY && item.keyData() == null;
    }

    private static DescribedKey asStated(StoredItem item) {
        return KeyDescriber.fromStatement(item.algorithm(), item.length());
    }

    private static void applyUpdates(Connection connection, List<ItemUpdate> updates) throws SQLException {
        if (updates.isEmpty()) {
            return;
        }
        try (PreparedStatement statement = connection.prepareStatement(UPDATE_DESCRIPTION)) {
            for (ItemUpdate update : updates) {
                boolean resetsCompliance = update.changesWhatComplianceReads();
                statement.setString(1, update.algorithm() == null ? null : update.algorithm().name());
                statement.setString(2, update.parameterSet());
                statement.setObject(3, update.length(), Types.INTEGER);
                statement.setBoolean(4, resetsCompliance);
                statement.setBoolean(5, resetsCompliance);
                statement.setObject(6, update.storedItem().uuid());
                statement.addBatch();
            }
            statement.executeBatch();
        }
        storeIdentifiers(connection, updates.stream().filter(ItemUpdate::gainsAnIdentifier).toList());
    }

    private static void storeIdentifiers(Connection connection, List<ItemUpdate> identified) throws SQLException {
        if (identified.isEmpty()) {
            return;
        }
        try (PreparedStatement statement = connection.prepareStatement(STORE_IDENTIFIER)) {
            for (ItemUpdate update : identified) {
                statement.setString(1, KeyFormat.ALGORITHM_IDENTIFIER.name());
                statement.setString(2, update.identifier());
                statement.setObject(3, update.storedItem().uuid());
                statement.addBatch();
            }
            statement.executeBatch();
        }
    }

    private static <E extends Enum<E>> E enumOrNull(Class<E> type, String name) {
        return name == null ? null : Enum.valueOf(type, name);
    }

    private record Page(List<StoredItem> readableItems, UUID lastScanned) {
    }

    record StoredItem(UUID uuid, UUID keyUuid, KeyType type, KeyAlgorithm algorithm, String parameterSet,
            Integer length, KeyFormat format, String keyData, KeyState state) {

        KeyHalf half() {
            return new KeyHalf(type, algorithm, length, new KeyMaterial(format, keyData));
        }

        ItemUpdate updatedTo(DescribedKey described) {
            return identifiedAs(described, KEEPS_ITS_KEY_DATA);
        }

        ItemUpdate identifiedAs(DescribedKey described, String identifier) {
            KeyAlgorithm newAlgorithm = described.algorithm() == null ? algorithm : described.algorithm();
            return new ItemUpdate(this, newAlgorithm, described.parameterSet(), described.length(), identifier);
        }
    }

    record ItemUpdate(StoredItem storedItem, KeyAlgorithm algorithm, String parameterSet, Integer length,
            String identifier) {

        boolean changesTheRow() {
            return changesWhatComplianceReads() || !Objects.equals(storedItem.parameterSet(), parameterSet);
        }

        boolean changesWhatComplianceReads() {
            return storedItem.algorithm() != algorithm || !Objects.equals(storedItem.length(), length)
                    || gainsAnIdentifier();
        }

        boolean gainsAnIdentifier() {
            return identifier != null;
        }
    }
}
