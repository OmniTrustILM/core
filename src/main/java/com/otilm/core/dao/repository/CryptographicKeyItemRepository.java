package com.otilm.core.dao.repository;

import com.otilm.core.dao.entity.CryptographicKey;
import com.otilm.core.dao.entity.CryptographicKeyItem;
import java.util.Collection;
import java.util.List;
import java.util.Optional;
import java.util.UUID;
import org.springframework.data.jpa.repository.EntityGraph;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

@Repository
public interface CryptographicKeyItemRepository extends SecurityFilterRepository<CryptographicKeyItem, UUID> {

    Optional<CryptographicKeyItem> findByUuid(UUID uuid);

    Optional<CryptographicKeyItem> findByFingerprint(String fingerprint);

    /**
     * The fingerprints from {@code fingerprints} that inventory already holds.
     */
    @Query("SELECT k.fingerprint FROM CryptographicKeyItem k WHERE k.fingerprint IN :fingerprints")
    List<String> findKnownFingerprints(@Param("fingerprints") Collection<String> fingerprints);

    Optional<CryptographicKeyItem> findByUuidAndKey(UUID uuid, CryptographicKey cryptographicKey);

    @EntityGraph(attributePaths = {"key", "key.tokenProfile"})
    List<CryptographicKeyItem> findByUuidIn(List<UUID> uuids);

    /**
     * The key items named by the uuid list. Deliberately carries no ordering: the ordering the listing asked for lives
     * in the rank of that list, and an ORDER BY here would replace it. Callers rank the result with
     * {@code SortOrderBuilder.rankBy}.
     */
    @EntityGraph(attributePaths = {"key", "key.tokenProfile", "key.groups", "key.owner"})
    List<CryptographicKeyItem> findFullByUuidIn(List<UUID> uuids);

    @EntityGraph(attributePaths = {"key", "key.items"})
    List<CryptographicKeyItem> findWithKeyByUuidIn(List<UUID> uuids);

    List<CryptographicKeyItem> findByKeyUuidIn(List<UUID> keyUuids);

    List<CryptographicKeyItem> findByKeyReferenceUuid(UUID keyReferenceUuid);

    List<CryptographicKeyItem> findByKeyTokenProfileUuid(UUID tokenProfileUuid);

    /**
     * @return the number of rows inserted — 1 when this caller inserted the item, 0 when an item with the same
     * fingerprint already existed and the caller must resolve the surviving key by fingerprint
     */
    @Modifying
    @Query(value = """
            INSERT INTO {h-schema}cryptographic_key_item (
                uuid, name, type, key_reference_uuid, key_uuid, key_algorithm, format, key_data,
                state, enabled, length, fingerprint, reason, compliance_status, created_at, updated_at, usage
            ) VALUES (
                :#{#cki.uuid}, :#{#cki.name}, :#{#cki.type.name()}, :#{#cki.keyReferenceUuid}, :#{#cki.keyUuid},
                :#{#cki.keyAlgorithm.name()}, :#{#cki.format?.name() ?: null}, :#{#cki.keyData}, :#{#cki.state.name()}, :#{#cki.enabled},
                :#{#cki.length}, :#{#cki.fingerprint}, :#{#cki.reason?.name() ?: null}, :#{#cki.complianceStatus.name()}, :#{#cki.createdAt},
                :#{#cki.updatedAt}, :#{#cki.usageBitmask}
            ) ON CONFLICT (fingerprint) DO NOTHING
            """,
            nativeQuery = true)
    Integer insertWithFingerprintConflictResolve(@Param("cki") CryptographicKeyItem keyItem);

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

    @EntityGraph(attributePaths = {"key", "key.tokenInstanceReference", "key.tokenInstanceReference.connector"})
    Optional<CryptographicKeyItem> findWithConnectorByUuid(UUID uuid);
}
