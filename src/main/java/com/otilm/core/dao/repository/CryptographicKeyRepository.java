package com.otilm.core.dao.repository;

import com.otilm.core.dao.entity.CryptographicKey;
import com.otilm.core.model.crypto.CryptographicKeyBasicModel;
import com.otilm.core.model.crypto.CryptographicKeyFullModel;
import com.otilm.core.model.crypto.ImmutableCryptographicKeyBasicModel;
import com.otilm.core.model.crypto.ImmutableCryptographicKeyFullModel;
import jakarta.persistence.LockModeType;
import java.util.List;
import java.util.Optional;
import java.util.UUID;
import org.springframework.data.jpa.repository.EntityGraph;
import org.springframework.data.jpa.repository.Lock;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

@Repository
public interface CryptographicKeyRepository extends SecurityFilterRepository<CryptographicKey, UUID> {

    Optional<CryptographicKey> findByUuid(UUID uuid);

    @Lock(LockModeType.PESSIMISTIC_WRITE)
    @Query("SELECT key FROM CryptographicKey key WHERE key.uuid = :uuid")
    Optional<CryptographicKey> findForUpdateByUuid(@Param("uuid") UUID uuid);

    @EntityGraph(attributePaths = {"groups", "owner", "items"})
    Optional<CryptographicKey> findWithAssociationsByUuid(UUID uuid);

    @EntityGraph(attributePaths = {"groups"})
    Optional<CryptographicKey> findWithGroupsByUuid(UUID uuid);

    @EntityGraph(attributePaths = {
            "groups",
            "owner",
            "items",
            "certificates",
            "altCertificates",
            "tokenProfile",
            "tokenInstanceReference.connectorInterface",
            "tokenInstanceReference.tokenProfiles"})
    Optional<CryptographicKey> findWithModelAssociationsByUuid(UUID uuid);

    default Optional<CryptographicKeyBasicModel> findBasicModelByUuid(UUID uuid) {
        return findWithGroupsByUuid(uuid).map(ImmutableCryptographicKeyBasicModel::from);
    }

    default Optional<CryptographicKeyFullModel> findFullModelByUuid(UUID uuid) {
        return findWithModelAssociationsByUuid(uuid).map(ImmutableCryptographicKeyFullModel::from);
    }

    /**
     * Loads the key with everything the signing path dereferences: its token profile, its key items, and the token
     * instance reference used to resolve the connector. Callers that sign outside a transaction must use this finder
     * rather than {@link #findByUuid(UUID)} so the traversal does not depend on open-session-in-view.
     */
    @EntityGraph(attributePaths = {"tokenProfile", "items", "tokenInstanceReference"})
    Optional<CryptographicKey> findWithKeyItemsAndTokenByUuid(UUID uuid);

    Optional<CryptographicKey> findByName(String name);

    @EntityGraph(attributePaths = {"tokenProfile", "items"})
    List<CryptographicKey> findByUuidIn(List<UUID> uuids);

    long countByTokenProfileUuid(UUID tokenProfileUuid);

    /** Counts links, including both roles when the same certificate references a key twice. */
    @Query("""
            SELECT key.uuid AS uuid,
                SUM(CASE WHEN certificate.keyUuid = key.uuid THEN 1 ELSE 0 END
                    + CASE WHEN certificate.altKeyUuid = key.uuid THEN 1 ELSE 0 END) AS associations
            FROM CryptographicKey key
            LEFT JOIN Certificate certificate ON certificate.keyUuid = key.uuid OR certificate.altKeyUuid = key.uuid
            WHERE key.uuid IN :uuids
            GROUP BY key.uuid
            """)
    List<KeyCertificateAssociationCount> getCertificateAssociationCounts(@Param("uuids") List<UUID> uuids);

    interface KeyCertificateAssociationCount {
        UUID getUuid();

        long getAssociations();
    }
}
