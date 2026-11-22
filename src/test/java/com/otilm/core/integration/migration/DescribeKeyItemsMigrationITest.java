package com.otilm.core.integration.migration;

import com.otilm.api.model.common.enums.cryptography.KeyAlgorithm;
import com.otilm.api.model.common.enums.cryptography.KeyFormat;
import com.otilm.api.model.common.enums.cryptography.KeyType;
import com.otilm.api.model.core.compliance.ComplianceStatus;
import com.otilm.api.model.core.cryptography.key.KeyState;
import com.otilm.core.dao.entity.CryptographicKey;
import com.otilm.core.dao.entity.CryptographicKeyItem;
import com.otilm.core.dao.repository.CryptographicKeyItemRepository;
import com.otilm.core.dao.repository.CryptographicKeyRepository;
import com.otilm.core.model.compliance.ComplianceResultDto;
import com.otilm.core.model.crypto.KeyMaterial;
import com.otilm.core.util.CryptographyUtil;
import com.otilm.core.util.PqcKeyFixtures;
import com.otilm.core.util.TestDatabaseCleaner;
import com.otilm.core.util.TestPublicKeys;
import com.zaxxer.hikari.HikariDataSource;
import db.migration.V202611211201__DescribeKeyItems;
import java.io.IOException;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.lang.reflect.Proxy;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PublicKey;
import java.security.spec.ECGenParameterSpec;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.time.OffsetDateTime;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.UUID;
import javax.sql.DataSource;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.jcajce.spec.MLKEMParameterSpec;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.flywaydb.core.api.migration.Context;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.NullSource;
import org.junit.jupiter.params.provider.ValueSource;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.core.io.ClassPathResource;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class DescribeKeyItemsMigrationITest extends BaseMigrationTest {

    private static final int TWO_ITEMS_PER_PAGE = 2;
    private static final Material NO_MATERIAL = null;
    private static final UUID ON_PAGE_ONE = UUID.fromString("00000000-0000-0000-0000-000000000001");
    private static final UUID ALSO_ON_PAGE_ONE = UUID.fromString("00000000-0000-0000-0000-000000000002");
    private static final UUID ON_PAGE_TWO = UUID.fromString("00000000-0000-0000-0000-000000000003");
    private static final String PARAMETER_SET_COLUMN_MIGRATION = "db/migration/V202611211200__cryptographic_key_item_parameter_set.sql";
    private static final String PARAMETER_SET_INDEX_MIGRATION = "db/migration/V202611211202__cryptographic_key_item_parameter_set_index.sql";
    private static final String PREVIOUS_SCHEMA = "describe_key_items_upgrade_check";

    @Autowired
    private DataSource dataSource;
    @Autowired
    private CryptographicKeyRepository cryptographicKeyRepository;
    @Autowired
    private CryptographicKeyItemRepository cryptographicKeyItemRepository;

    @Test
    void describesEachPublicItemFromItsSpki_whenTheItemsSpanSeveralPages() throws Exception {
        // given
        var p256StoredWithItsPointSize = storedItem(storedKey(), KeyType.PUBLIC_KEY, KeyAlgorithm.ECDSA, 512,
                spki(ecPublicKey("secp256r1")));
        var mlKemCertificateKey = storedItem(storedKey(), KeyType.PUBLIC_KEY, KeyAlgorithm.UNKNOWN, null,
                spki(mlKem768PublicKey()));
        var rsaPublic = storedItem(storedKey(), KeyType.PUBLIC_KEY, KeyAlgorithm.RSA, 2048,
                spki(TestPublicKeys.rsaPublicKey()));

        // when
        migrate();

        // then
        assertThat(describedAs(p256StoredWithItsPointSize)).isEqualTo(new Stored(KeyAlgorithm.ECDSA, "P-256", 256));
        assertThat(describedAs(mlKemCertificateKey)).isEqualTo(new Stored(KeyAlgorithm.MLKEM, "ML-KEM-768", 9472));
        assertThat(describedAs(rsaPublic)).isEqualTo(new Stored(KeyAlgorithm.RSA, null, 2048));
    }

    @Test
    void givesAPrivateItemItsSiblingsIdentifierWithoutAFingerprint_whenTheTokenAloneHoldsIt() throws Exception {
        // given
        var publicKey = PqcKeyFixtures.keyPair().getPublic();
        var mlDsaPair = storedKey();
        storedItem(mlDsaPair, KeyType.PUBLIC_KEY, KeyAlgorithm.MLDSA, 15616, spki(publicKey));
        var privateStoredWithThePublicLength = storedItem(mlDsaPair, KeyType.PRIVATE_KEY, KeyAlgorithm.MLDSA, 15616,
                NO_MATERIAL);
        var spkiIdentifier = identifierOf(publicKey);

        // when
        migrate();

        // then
        assertThat(describedAs(privateStoredWithThePublicLength))
                .isEqualTo(new Stored(KeyAlgorithm.MLDSA, "ML-DSA-65", 32256));
        assertThat(materialOf(privateStoredWithThePublicLength))
                .isEqualTo(new Material(KeyFormat.ALGORITHM_IDENTIFIER, spkiIdentifier));
        assertThat(fingerprintOf(privateStoredWithThePublicLength)).isNull();
    }

    @Test
    void leavesAPrivateItemUnnamedWithoutItsEcLength_whenItsPublicSiblingsDisagree() throws Exception {
        // given
        var disagreeingKey = storedKey();
        storedItem(disagreeingKey, KeyType.PUBLIC_KEY, KeyAlgorithm.ECDSA, 256, spki(ecPublicKey("secp256r1")));
        storedItem(disagreeingKey, KeyType.PUBLIC_KEY, KeyAlgorithm.ECDSA, 384, spki(ecPublicKey("secp384r1")));
        var privateItem = storedItem(disagreeingKey, KeyType.PRIVATE_KEY, KeyAlgorithm.ECDSA, 256, NO_MATERIAL);

        // when
        migrate();

        // then
        assertThat(describedAs(privateItem)).isEqualTo(new Stored(KeyAlgorithm.ECDSA, null, null));
        assertThat(materialOf(privateItem)).isEqualTo(NO_MATERIAL);
    }

    @Test
    void describesAV1PrivateItemByItsStatement_whenItHoldsOnlyCustomKeyData() throws Exception {
        // given
        var customKeyData = new Material(KeyFormat.CUSTOM, "{\"curve.name\":\"secp384r1\"}");
        var v1Private = storedItem(storedKey(), KeyType.PRIVATE_KEY, KeyAlgorithm.ECDSA, 768, customKeyData);

        // when
        migrate();

        // then
        assertThat(describedAs(v1Private)).isEqualTo(new Stored(KeyAlgorithm.ECDSA, null, null));
        assertThat(materialOf(v1Private)).isEqualTo(customKeyData);
    }

    @Test
    void leavesADestroyedPrivateItemUnnamed_whenItsPublicSiblingSurvives() throws Exception {
        // given
        var pair = storedKey();
        storedItem(pair, KeyType.PUBLIC_KEY, KeyAlgorithm.ECDSA, 256, spki(ecPublicKey("secp256r1")));
        var destroyed = destroyed(storedItem(pair, KeyType.PRIVATE_KEY, KeyAlgorithm.ECDSA, 256, NO_MATERIAL));

        // when
        migrate();

        // then
        assertThat(describedAs(destroyed)).isEqualTo(new Stored(KeyAlgorithm.ECDSA, null, null));
        assertThat(materialOf(destroyed)).isEqualTo(NO_MATERIAL);
    }

    @Test
    void clearsTheComplianceResult_whenTheSizeChanges() throws Exception {
        // given
        var p256StoredWithItsPointSize = checkedCompliant(
                storedItem(storedKey(), KeyType.PUBLIC_KEY, KeyAlgorithm.ECDSA, 512, spki(ecPublicKey("secp256r1"))));

        // when
        migrate();

        // then
        assertThat(complianceOf(p256StoredWithItsPointSize)).isEqualTo(ComplianceStatus.NOT_CHECKED);
        assertThat(columnOf(p256StoredWithItsPointSize, "compliance_result")).isNull();
    }

    @Test
    void keepsTheComplianceResult_whenTheItemGainsOnlyItsName() throws Exception {
        // given
        var p384StoredWithItsFieldSize = checkedCompliant(
                storedItem(storedKey(), KeyType.PUBLIC_KEY, KeyAlgorithm.ECDSA, 384, spki(ecPublicKey("secp384r1"))));

        // when
        migrate();

        // then
        assertThat(complianceOf(p384StoredWithItsFieldSize)).isEqualTo(ComplianceStatus.OK);
        assertThat(columnOf(p384StoredWithItsFieldSize, "compliance_result")).isNotNull();
    }

    @Test
    void changesNothing_whenRunAgain() throws Exception {
        // given
        var pair = storedKey();
        storedItem(pair, KeyType.PUBLIC_KEY, KeyAlgorithm.ECDSA, 512, spki(ecPublicKey("secp256r1")));
        var privateItem = storedItem(pair, KeyType.PRIVATE_KEY, KeyAlgorithm.ECDSA, 256, NO_MATERIAL);
        migrate();
        checkedCompliant(privateItem);

        // when
        migrate();

        // then
        assertThat(complianceOf(privateItem)).isEqualTo(ComplianceStatus.OK);
    }

    @Test
    void describesAPrivateItemByItsSibling_whenTheSiblingIsOnAnEarlierPage() throws Exception {
        // given
        var pair = storedKey();
        renumbered(storedItem(pair, KeyType.PUBLIC_KEY, KeyAlgorithm.ECDSA, 256, spki(ecPublicKey("secp256r1"))),
                ON_PAGE_ONE);
        renumbered(storedItem(storedKey(), KeyType.PUBLIC_KEY, KeyAlgorithm.RSA, 2048,
                spki(TestPublicKeys.rsaPublicKey())), ALSO_ON_PAGE_ONE);
        var privateItem = renumbered(storedItem(pair, KeyType.PRIVATE_KEY, KeyAlgorithm.ECDSA, 512, NO_MATERIAL),
                ON_PAGE_TWO);

        // when
        migrate();

        // then
        assertThat(describedAs(privateItem)).isEqualTo(new Stored(KeyAlgorithm.ECDSA, "P-256", 256));
    }

    @Test
    void takesTheAlgorithmItsSiblingNames_whenAPrivateItemStatesAnother() throws Exception {
        // given
        var p256PublicKey = ecPublicKey("secp256r1");
        var mismatchedKey = storedKey();
        storedItem(mismatchedKey, KeyType.PUBLIC_KEY, KeyAlgorithm.ECDSA, 256, spki(p256PublicKey));
        var statedAsRsa = storedItem(mismatchedKey, KeyType.PRIVATE_KEY, KeyAlgorithm.RSA, 2048, NO_MATERIAL);

        // when
        migrate();

        // then
        assertThat(describedAs(statedAsRsa)).isEqualTo(new Stored(KeyAlgorithm.ECDSA, "P-256", 256));
        assertThat(materialOf(statedAsRsa))
                .isEqualTo(new Material(KeyFormat.ALGORITHM_IDENTIFIER, identifierOf(p256PublicKey)));
    }

    @Test
    void takesTheAlgorithmItsKeyDataNames_whenAV1ItemStatesAnother() throws Exception {
        // given
        var p384Pkcs8 = new Material(KeyFormat.PRKI,
                Base64.getEncoder().encodeToString(ecKeyPair("secp384r1").getPrivate().getEncoded()));
        var statedAsRsa = storedItem(storedKey(), KeyType.PRIVATE_KEY, KeyAlgorithm.RSA, 2048, p384Pkcs8);

        // when
        migrate();

        // then
        assertThat(describedAs(statedAsRsa)).isEqualTo(new Stored(KeyAlgorithm.ECDSA, "P-384", 384));
    }

    @ParameterizedTest
    @NullSource
    @ValueSource(ints = 4096)
    void describesAV1RsaPrivateItemByItsModulus_whenItsStoredLengthIsWrongOrAbsent(Integer storedLength)
            throws Exception {
        // given
        var rsa2048Pkcs8 = new Material(KeyFormat.PRKI,
                Base64.getEncoder().encodeToString(rsaKeyPair(2048).getPrivate().getEncoded()));
        var v1Private = storedItem(storedKey(), KeyType.PRIVATE_KEY, KeyAlgorithm.RSA, storedLength, rsa2048Pkcs8);

        // when
        migrate();

        // then
        assertThat(describedAs(v1Private)).isEqualTo(new Stored(KeyAlgorithm.RSA, null, 2048));
    }

    @Test
    void keepsTheFingerprint_whenAPublicItemsSizeChanges() throws Exception {
        // given
        var p256Spki = spki(ecPublicKey("secp256r1"));
        var p256StoredWithItsPointSize = storedItem(storedKey(), KeyType.PUBLIC_KEY, KeyAlgorithm.ECDSA, 512, p256Spki);

        // when
        migrate();

        // then
        assertThat(describedAs(p256StoredWithItsPointSize).length()).isEqualTo(256);
        assertThat(fingerprintOf(p256StoredWithItsPointSize)).isNotNull().isEqualTo(fingerprintOf(p256Spki));
    }

    @Test
    void bindsNoKeyData_whenARowChangesOnlyItsDescription() throws Exception {
        // given
        var pkcs8 = new Material(KeyFormat.PRKI,
                Base64.getEncoder().encodeToString(ecKeyPair("secp384r1").getPrivate().getEncoded()));
        storedItem(storedKey(), KeyType.PRIVATE_KEY, KeyAlgorithm.ECDSA, 768, pkcs8);

        // when
        List<Object> binds = bindsWhileMigrating();

        // then
        assertThat(binds).contains("P-384").doesNotContain(pkcs8.keyData());
    }

    @Test
    void locksTheItemsAgainstConcurrentWrites_whileItRuns() throws Exception {
        // given
        storedItem(storedKey(), KeyType.PUBLIC_KEY, KeyAlgorithm.ECDSA, 512, spki(ecPublicKey("secp256r1")));

        // when
        List<String> heldModes = lockModesHeldWhileMigrating();

        // then
        assertThat(heldModes).contains("ExclusiveLock");
    }

    @Test
    void describesAndIndexesTheItems_whenUpgradingThePreviousSchema() throws Exception {
        // given
        var p256StoredWithItsPointSize = storedItem(storedKey(), KeyType.PUBLIC_KEY, KeyAlgorithm.ECDSA, 512,
                spki(ecPublicKey("secp256r1")));

        // when
        Upgrade upgrade = upgradedFromThePreviousSchema(p256StoredWithItsPointSize);

        // then
        assertThat(upgrade.described()).isEqualTo(new Stored(KeyAlgorithm.ECDSA, "P-256", 256));
        assertThat(upgrade.indexes()).contains("cryptographic_key_item_parameter_set");
    }

    // ── Helpers ───────────────────────────────────────────────────────────────

    private void migrate() throws Exception {
        inOneTransaction(connection -> {
            runMigration(connection);
            connection.commit();
            return null;
        });
    }

    private List<Object> bindsWhileMigrating() throws Exception {
        List<Object> binds = new ArrayList<>();
        inOneTransaction(connection -> {
            runMigration(recordingBinds(connection, binds));
            return null;
        });
        return binds;
    }

    private List<String> lockModesHeldWhileMigrating() throws Exception {
        return inOneTransaction(connection -> {
            runMigration(connection);
            return lockModesOfTheItems();
        });
    }

    /** The upgrade runs outside the pool. Its statements leave plans cached for the scratch schema. */
    private Upgrade upgradedFromThePreviousSchema(UUID itemUuid) throws Exception {
        TestDatabaseCleaner.requireValidSchemaName(dbSchema);
        HikariDataSource pool = dataSource.unwrap(HikariDataSource.class);
        try (Connection unpooled = DriverManager
                .getConnection(pool.getJdbcUrl(), pool.getUsername(), pool.getPassword())) {
            return inOneTransaction(unpooled, connection -> upgraded(connection, itemUuid));
        }
    }

    private Upgrade upgraded(Connection connection, UUID itemUuid) throws Exception {
        try (Statement statement = connection.createStatement()) {
            statement.execute("CREATE SCHEMA " + PREVIOUS_SCHEMA);
            statement
                    .execute("CREATE TABLE " + PREVIOUS_SCHEMA + ".cryptographic_key_item AS SELECT * FROM " + dbSchema
                            + ".cryptographic_key_item");
            statement.execute("ALTER TABLE " + PREVIOUS_SCHEMA + ".cryptographic_key_item DROP COLUMN parameter_set");
            statement.execute("SET search_path TO " + PREVIOUS_SCHEMA);
        }
        applySql(connection, PARAMETER_SET_COLUMN_MIGRATION);
        runMigration(connection);
        applySql(connection, PARAMETER_SET_INDEX_MIGRATION);
        return new Upgrade(describedAs(connection, itemUuid), indexesOfTheItems(connection));
    }

    private static void applySql(Connection connection, String migration) throws SQLException, IOException {
        try (Statement statement = connection.createStatement()) {
            statement.execute(new ClassPathResource(migration).getContentAsString(StandardCharsets.UTF_8));
        }
    }

    private <T> T inOneTransaction(TransactionWork<T> work) throws Exception {
        try (Connection connection = dataSource.getConnection()) {
            return inOneTransaction(connection, work);
        }
    }

    /** Runs the work in one transaction, as Flyway runs a migration. What the work leaves uncommitted rolls back. */
    private static <T> T inOneTransaction(Connection connection, TransactionWork<T> work) throws Exception {
        connection.setAutoCommit(false);
        try {
            return work.runIn(connection);
        } finally {
            connection.rollback();
            connection.setAutoCommit(true);
        }
    }

    private static void runMigration(Connection connection) throws SQLException {
        Context context = mock(Context.class);
        when(context.getConnection()).thenReturn(connection);
        new V202611211201__DescribeKeyItems(TWO_ITEMS_PER_PAGE).migrate(context);
    }

    private List<String> lockModesOfTheItems() throws SQLException {
        try (Connection observer = dataSource.getConnection();
                var statement = observer
                        .prepareStatement("SELECT mode FROM pg_locks"
                                + " WHERE relation = 'cryptographic_key_item'::regclass AND granted")) {
            return strings(statement);
        }
    }

    private static List<String> indexesOfTheItems(Connection connection) throws SQLException {
        try (var statement = connection
                .prepareStatement("SELECT indexname FROM pg_indexes WHERE schemaname = ?"
                        + " AND tablename = 'cryptographic_key_item'")) {
            statement.setString(1, PREVIOUS_SCHEMA);
            return strings(statement);
        }
    }

    private static List<String> strings(PreparedStatement statement) throws SQLException {
        List<String> values = new ArrayList<>();
        try (ResultSet rows = statement.executeQuery()) {
            while (rows.next()) {
                values.add(rows.getString(1));
            }
        }
        return values;
    }

    private static Connection recordingBinds(Connection connection, List<Object> binds) {
        return proxy(Connection.class, (method, args) -> {
            Object result = invoke(connection, method, args);
            return result instanceof PreparedStatement statement ? recordingBinds(statement, binds) : result;
        });
    }

    private static PreparedStatement recordingBinds(PreparedStatement statement, List<Object> binds) {
        return proxy(PreparedStatement.class, (method, args) -> {
            if (method.getName().startsWith("set") && args != null && args.length >= 2) {
                binds.add(args[1]);
            }
            return invoke(statement, method, args);
        });
    }

    private static <T> T proxy(Class<T> type, Delegation delegation) {
        return type
                .cast(Proxy
                        .newProxyInstance(type.getClassLoader(), new Class<?>[]{type},
                                (proxy, method, args) -> delegation.handle(method, args)));
    }

    private static Object invoke(Object target, Method method, Object[] args) throws Throwable {
        try {
            return method.invoke(target, args);
        } catch (InvocationTargetException e) {
            throw e.getCause();
        }
    }

    private UUID renumbered(UUID itemUuid, UUID fixedUuid) throws SQLException {
        try (Connection connection = dataSource.getConnection();
                var statement = connection
                        .prepareStatement("UPDATE cryptographic_key_item SET uuid = ? WHERE uuid = ?")) {
            statement.setObject(1, fixedUuid);
            statement.setObject(2, itemUuid);
            statement.executeUpdate();
        }
        return fixedUuid;
    }

    private CryptographicKey storedKey() {
        CryptographicKey key = new CryptographicKey();
        key.setName("stored before the migration");
        return cryptographicKeyRepository.saveAndFlush(key);
    }

    /** Stores an item as Core did before it described items. */
    private UUID storedItem(CryptographicKey key, KeyType type, KeyAlgorithm algorithm, Integer length,
            Material material) {
        CryptographicKeyItem item = new CryptographicKeyItem();
        item.setName(key.getName());
        item.setKey(key);
        item.setKeyUuid(key.getUuid());
        item.setType(type);
        item.setKeyAlgorithm(algorithm);
        item.setLength(length);
        item.setState(KeyState.ACTIVE);
        item.setEnabled(true);
        if (material != NO_MATERIAL) {
            item.setFormat(material.format());
            item.setKeyData(material.keyData());
            item.setFingerprint(fingerprintOf(material));
        }
        return cryptographicKeyItemRepository.saveAndFlush(item).getUuid();
    }

    private UUID destroyed(UUID itemUuid) {
        CryptographicKeyItem item = cryptographicKeyItemRepository.findById(itemUuid).orElseThrow();
        item.setState(KeyState.DESTROYED);
        cryptographicKeyItemRepository.saveAndFlush(item);
        return itemUuid;
    }

    private UUID checkedCompliant(UUID itemUuid) {
        ComplianceResultDto result = new ComplianceResultDto();
        result.setStatus(ComplianceStatus.OK);
        result.setTimestamp(OffsetDateTime.now());
        CryptographicKeyItem item = cryptographicKeyItemRepository.findById(itemUuid).orElseThrow();
        item.setComplianceStatus(ComplianceStatus.OK);
        item.setComplianceResult(result);
        cryptographicKeyItemRepository.saveAndFlush(item);
        return itemUuid;
    }

    private Stored describedAs(UUID itemUuid) throws SQLException {
        try (Connection connection = dataSource.getConnection()) {
            return describedAs(connection, itemUuid);
        }
    }

    private static Stored describedAs(Connection connection, UUID itemUuid) throws SQLException {
        try (var statement = connection
                .prepareStatement("SELECT key_algorithm, parameter_set, length FROM cryptographic_key_item"
                        + " WHERE uuid = ?")) {
            statement.setObject(1, itemUuid);
            try (ResultSet row = statement.executeQuery()) {
                row.next();
                return new Stored(KeyAlgorithm.valueOf(row.getString("key_algorithm")), row.getString("parameter_set"),
                        row.getObject("length", Integer.class));
            }
        }
    }

    private Material materialOf(UUID itemUuid) throws SQLException {
        try (Connection connection = dataSource.getConnection();
                var statement = connection
                        .prepareStatement("SELECT format, key_data FROM cryptographic_key_item WHERE uuid = ?")) {
            statement.setObject(1, itemUuid);
            try (ResultSet row = statement.executeQuery()) {
                row.next();
                String format = row.getString("format");
                return format == null
                        ? NO_MATERIAL
                        : new Material(KeyFormat.valueOf(format), row.getString("key_data"));
            }
        }
    }

    private String fingerprintOf(UUID itemUuid) throws SQLException {
        return columnOf(itemUuid, "fingerprint");
    }

    private static String fingerprintOf(Material material) {
        return CryptographyUtil.calculateKeyFingerprint(new KeyMaterial(material.format(), material.keyData()));
    }

    private ComplianceStatus complianceOf(UUID itemUuid) throws SQLException {
        return ComplianceStatus.valueOf(columnOf(itemUuid, "compliance_status"));
    }

    private String columnOf(UUID itemUuid, String column) throws SQLException {
        try (Connection connection = dataSource.getConnection();
                var statement = connection
                        .prepareStatement("SELECT " + column + " FROM cryptographic_key_item WHERE uuid = ?")) {
            statement.setObject(1, itemUuid);
            try (ResultSet row = statement.executeQuery()) {
                row.next();
                return row.getString(column);
            }
        }
    }

    private static PublicKey ecPublicKey(String curveName) throws GeneralSecurityException {
        return ecKeyPair(curveName).getPublic();
    }

    private static KeyPair ecKeyPair(String curveName) throws GeneralSecurityException {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("EC", new BouncyCastleProvider());
        generator.initialize(new ECGenParameterSpec(curveName));
        return generator.generateKeyPair();
    }

    private static KeyPair rsaKeyPair(int modulusBits) throws GeneralSecurityException {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(modulusBits);
        return generator.generateKeyPair();
    }

    private static PublicKey mlKem768PublicKey() throws GeneralSecurityException {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("ML-KEM", new BouncyCastleProvider());
        generator.initialize(MLKEMParameterSpec.ml_kem_768);
        return generator.generateKeyPair().getPublic();
    }

    private static Material spki(PublicKey publicKey) {
        return new Material(KeyFormat.SPKI, Base64.getEncoder().encodeToString(publicKey.getEncoded()));
    }

    private static String identifierOf(PublicKey publicKey) throws IOException {
        var identifier = SubjectPublicKeyInfo.getInstance(publicKey.getEncoded()).getAlgorithm();
        return Base64.getEncoder().encodeToString(identifier.getEncoded());
    }

    private record Material(KeyFormat format, String keyData) {
    }

    private record Stored(KeyAlgorithm algorithm, String parameterSet, Integer length) {
    }

    private record Upgrade(Stored described, List<String> indexes) {
    }

    @FunctionalInterface
    private interface TransactionWork<T> {
        T runIn(Connection connection) throws Exception;
    }

    @FunctionalInterface
    private interface Delegation {
        Object handle(Method method, Object[] args) throws Throwable;
    }
}
