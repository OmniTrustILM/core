package com.otilm.core.dao.repository;

import com.otilm.core.dao.entity.CryptographicKeyItem;
import com.otilm.core.model.crypto.CryptographicKeyItemBasicModel;
import com.otilm.core.model.crypto.CryptographicKeyItemOperationRow;
import jakarta.persistence.LockModeType;
import java.util.Collection;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;
import org.springframework.data.jpa.repository.EntityGraph;
import org.springframework.data.jpa.repository.Lock;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

@Repository
public interface CryptographicKeyItemRepository extends SecurityFilterRepository<CryptographicKeyItem, UUID> {

    Optional<CryptographicKeyItem> findByUuid(UUID uuid);

    @Lock(LockModeType.PESSIMISTIC_WRITE)
    @Query("SELECT item FROM CryptographicKeyItem item WHERE item.uuid = :uuid")
    Optional<CryptographicKeyItem> findForUpdateByUuid(@Param("uuid") UUID uuid);

    /** Deletes without loading the item; the database foreign key cascades deletion to its event history. */
    @Modifying(flushAutomatically = true, clearAutomatically = true)
    @Query("DELETE FROM CryptographicKeyItem item WHERE item.uuid = :uuid")
    int deleteItemByUuid(@Param("uuid") UUID uuid);

    @EntityGraph(attributePaths = {"key", "key.tokenProfile", "key.tokenInstanceReference"})
    Optional<CryptographicKeyItem> findWithAuthorizationContextByUuid(UUID uuid);

    /** Flushes pending changes and clears the persistence context after the bulk update. */
    @Modifying(flushAutomatically = true, clearAutomatically = true)
    @Query("""
            UPDATE CryptographicKeyItem item
            SET item.enabled = :enabled, item.updatedAt = CURRENT_TIMESTAMP
            WHERE item.uuid = :uuid AND item.enabled <> :enabled
            """)
    int updateEnabledIfChanged(@Param("uuid") UUID uuid, @Param("enabled") boolean enabled);

    /**
     * Clears the export permission.
     *
     * @param uuid non-null UUID of the key item
     * @return one if the item was exportable and is no longer; zero if it does not exist or already was not
     */
    @Modifying(flushAutomatically = true, clearAutomatically = true)
    @Query("""
            UPDATE CryptographicKeyItem item
            SET item.exportable = FALSE, item.updatedAt = CURRENT_TIMESTAMP
            WHERE item.uuid = :uuid AND item.exportable = TRUE
            """)
    int clearExportableIfSet(@Param("uuid") UUID uuid);

    /**
     * Clears key material and marks the item destroyed while preserving its current compromise classification.
     *
     * @param uuid non-null UUID of the key item to finalize
     * @return one if the item exists, including an already destroyed item; zero if it does not exist
     */
    @Modifying(flushAutomatically = true, clearAutomatically = true)
    @Query("""
            UPDATE CryptographicKeyItem item
            SET item.keyData = NULL,
                item.state = CASE
                    WHEN item.state IN (com.otilm.api.model.core.cryptography.key.KeyState.COMPROMISED,
                                        com.otilm.api.model.core.cryptography.key.KeyState.DESTROYED_COMPROMISED)
                        THEN com.otilm.api.model.core.cryptography.key.KeyState.DESTROYED_COMPROMISED
                    ELSE com.otilm.api.model.core.cryptography.key.KeyState.DESTROYED
                END,
                item.updatedAt = CURRENT_TIMESTAMP
            WHERE item.uuid = :uuid
            """)
    int finalizeKeyItemDestruction(@Param("uuid") UUID uuid);

    Optional<CryptographicKeyItem> findByFingerprint(String fingerprint);

    /**
     * The fingerprints from {@code fingerprints} that inventory already holds.
     */
    @Query("SELECT k.fingerprint FROM CryptographicKeyItem k WHERE k.fingerprint IN :fingerprints")
    List<String> findKnownFingerprints(@Param("fingerprints") Collection<String> fingerprints);

    Optional<CryptographicKeyItem> findByUuidAndKeyUuid(UUID uuid, UUID cryptographicKeyUuid);

    @Query("""
            SELECT COUNT(item) > 0 FROM CryptographicKeyItem item
            WHERE item.uuid = :uuid AND item.keyUuid = :keyUuid
            """)
    boolean isItemOfKey(@Param("uuid") UUID uuid, @Param("keyUuid") UUID keyUuid);

    @Lock(LockModeType.PESSIMISTIC_WRITE)
    @Query("SELECT item FROM CryptographicKeyItem item WHERE item.uuid = :uuid AND item.keyUuid = :keyUuid")
    Optional<CryptographicKeyItem> findForUpdateByUuidAndKeyUuid(@Param("uuid") UUID uuid,
            @Param("keyUuid") UUID keyUuid);

    @EntityGraph(attributePaths = {"key", "key.tokenProfile"})
    List<CryptographicKeyItem> findByUuidIn(List<UUID> uuids);

    /**
     * Loads immutable basic models for the key items matching the supplied UUIDs.
     *
     * @param uuids non-null list of key-item UUIDs; may be empty
     * @return immutable list of matching models in unspecified order; missing items are omitted
     */
    default List<CryptographicKeyItemBasicModel> findBasicModelsByUuidIn(List<UUID> uuids) {
        if (uuids.isEmpty()) {
            return List.of();
        }
        return findByUuidIn(uuids).stream().map(CryptographicKeyItemBasicModel::from).toList();
    }

    /**
     * The key items named by the uuid list. Deliberately carries no ordering: the ordering the listing asked for lives
     * in the rank of that list, and an ORDER BY here would replace it. Callers rank the result with
     * {@code SortOrderBuilder.rankBy}.
     */
    @EntityGraph(attributePaths = {"key", "key.tokenProfile", "key.tokenInstanceReference", "key.groups", "key.owner"})
    List<CryptographicKeyItem> findFullByUuidIn(List<UUID> uuids);

    List<CryptographicKeyItem> findByKeyUuidIn(List<UUID> keyUuids);

    boolean existsByKeyUuid(UUID keyUuid);

    /**
     * Returns the remote key reference UUIDs stored for the specified token instance, regardless of key state.
     *
     * @param tokenInstanceUuid non-null Core UUID of the token instance
     * @return distinct, non-null remote key reference UUIDs, or an empty set if none exist for the token instance
     */
    @Query("""
            SELECT DISTINCT item.keyReferenceUuid
            FROM CryptographicKeyItem item
            WHERE item.key.tokenInstanceReferenceUuid = :tokenInstanceUuid
              AND item.keyReferenceUuid IS NOT NULL
            """)
    Set<UUID> findKeyReferenceUuidsByTokenInstanceUuid(@Param("tokenInstanceUuid") UUID tokenInstanceUuid);

    List<CryptographicKeyItem> findByKeyTokenProfileUuid(UUID tokenProfileUuid);

    /**
     * @return the number of rows inserted — 1 when this caller inserted the item, 0 when an item with the same
     * fingerprint already existed and the caller must resolve the surviving key by fingerprint
     */
    @Modifying(flushAutomatically = true)
    @Query(value = """
            INSERT INTO {h-schema}cryptographic_key_item (
                uuid, name, type, key_reference_uuid, key_uuid, key_algorithm, format, key_data,
                state, enabled, length, fingerprint, reason, compliance_status, created_at, updated_at, usage,
                exportable, key_meta
            ) VALUES (
                :#{#cki.uuid}, :#{#cki.name}, :#{#cki.type.name()}, :#{#cki.keyReferenceUuid}, :#{#cki.keyUuid},
                :#{#cki.keyAlgorithm.name()}, :#{#cki.format?.name() ?: null}, :#{#cki.keyData}, :#{#cki.state.name()}, :#{#cki.enabled},
                :#{#cki.length}, :#{#cki.fingerprint}, :#{#cki.reason?.name() ?: null}, :#{#cki.complianceStatus.name()}, :#{#cki.createdAt},
                :#{#cki.updatedAt}, :#{#cki.usageBitmask}, :#{#cki.exportable}, CAST(:keyMeta AS jsonb)
            ) ON CONFLICT (fingerprint) DO NOTHING
            """,
            nativeQuery = true)
    Integer insertWithFingerprintConflictResolve(@Param("cki") CryptographicKeyItem keyItem,
            @Param("keyMeta") String keyMeta);

    /**
     * How many certificates each of the named key items is associated with, keyed by the item's uuid.
     *
     * <p>
     * Returns the uuid rather than counts alone because the caller has to line each count up with its key item. Two
     * queries ordered by the same non-unique column line up only while that column has no ties, and once the listing
     * orders by a field the request names they do not line up at all.
     */
    @Query(value = """
            SELECT cki.uuid AS uuid, COUNT(c.uuid) AS associations
                FROM CryptographicKeyItem cki
                JOIN cki.key ck
                LEFT JOIN Certificate c
                    ON c.keyUuid = ck.uuid
                    OR c.altKeyUuid = ck.uuid
                WHERE cki.uuid IN :uuids
                GROUP BY cki.uuid
            """)
    List<KeyItemAssociationCount> getCountsOfAssociations(@Param("uuids") List<UUID> uuids);

    /** One key item's certificate-association count. */
    interface KeyItemAssociationCount {

        UUID getUuid();

        int getAssociations();
    }

    @Query("""
            SELECT new com.otilm.core.model.crypto.CryptographicKeyItemOperationRow(
                item.uuid, item.enabled, item.keyAlgorithm, item.state, item.type, item.usage, item.keyData,
                item.keyReferenceUuid, item.keyMeta, key.uuid, token.connectorUuid, token.tokenInstanceUuid,
                iface.interfaceCode, iface.version)
            FROM CryptographicKeyItem item
            JOIN item.key key
            JOIN key.tokenInstanceReference token
            LEFT JOIN token.connectorInterface iface
            WHERE item.uuid = :uuid
            """)
    Optional<CryptographicKeyItemOperationRow> findOperationRowByUuid(@Param("uuid") UUID uuid);
}
