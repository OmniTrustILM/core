package com.czertainly.core.dao.repository;

import com.czertainly.core.dao.entity.CryptographicKey;
import com.czertainly.core.dao.entity.CryptographicKeyItem;
import org.springframework.data.jpa.repository.EntityGraph;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;
import java.util.UUID;

@Repository
public interface CryptographicKeyItemRepository extends SecurityFilterRepository<CryptographicKeyItem, UUID> {

    Optional<CryptographicKeyItem> findByUuid(UUID uuid);

    Optional<CryptographicKeyItem> findByFingerprint(String fingerprint);

    Optional<CryptographicKeyItem> findByUuidAndKey(UUID uuid, CryptographicKey cryptographicKey);

    @EntityGraph(attributePaths = {"key", "key.tokenProfile"})
    List<CryptographicKeyItem> findByUuidIn(List<UUID> uuids);

    @EntityGraph(attributePaths = {"key", "key.tokenProfile", "key.groups", "key.owner"})
    List<CryptographicKeyItem> findFullByUuidInOrderByCreatedAtDesc(List<UUID> uuids);

    @EntityGraph(attributePaths = {"key", "key.items"})
    List<CryptographicKeyItem> findWithKeyByUuidIn(List<UUID> uuids);

    List<CryptographicKeyItem> findByKeyUuidIn(List<UUID> keyUuids);

    List<CryptographicKeyItem> findByKeyReferenceUuid(UUID keyReferenceUuid);

    List<CryptographicKeyItem> findByKeyTokenProfileUuid(UUID tokenProfileUuid);

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
            """, nativeQuery = true)
    void insertWithFingerprintConflictResolve(@Param("cki") CryptographicKeyItem keyItem);

    @Query(value = """
            SELECT COUNT(c.uuid)
                FROM CryptographicKeyItem cki
                JOIN cki.key ck
                LEFT JOIN Certificate c
                    ON c.keyUuid = ck.uuid
                    OR c.altKeyUuid = ck.uuid
                WHERE cki.uuid IN :uuids
                GROUP BY cki.uuid
                ORDER BY cki.createdAt DESC
            """)
    List<Integer> getCountsOfAssociations(@Param("uuids") List<UUID> uuids);

    @EntityGraph(attributePaths = {
            "key",
            "key.tokenInstanceReference",
            "key.tokenInstanceReference.connector"
    })
    Optional<CryptographicKeyItem> findWithConnectorByUuid(UUID uuid);
}
