package com.otilm.core.dao.repository;

import java.util.List;
import java.util.Set;
import java.util.UUID;

import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import com.otilm.core.dao.entity.Cbom;

@Repository
public interface CbomRepository extends SecurityFilterRepository<Cbom, UUID> {

    @Query("""
            SELECT c2
            FROM Cbom c1
            JOIN Cbom c2
                ON c1.serialNumber = c2.serialNumber
            WHERE c1.uuid = :uuid
            ORDER BY c2.version DESC
            """)
    List<Cbom> findVersionsByUuid(@Param("uuid") UUID uuid);

    boolean existsBySerialNumberAndVersion(String serialNumber, int version);

    @Query("SELECT c.uuid FROM Cbom c WHERE c.uuid IN :uuids")
    Set<UUID> findExistingUuids(@Param("uuids") List<UUID> uuids);
}
