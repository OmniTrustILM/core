package com.czertainly.core.dao.repository;

import com.czertainly.core.dao.entity.CrlEntry;
import com.czertainly.core.dao.entity.CrlEntryId;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.stereotype.Repository;

import java.util.Date;
import java.util.List;
import java.util.Optional;
import java.util.UUID;

@Repository
public interface CrlEntryRepository extends SecurityFilterRepository<CrlEntry, Long> {

    Optional<CrlEntry> findById(CrlEntryId id);

    void deleteAllByCrlUuid(UUID crlUuid);

    @Modifying
    @Query(value = """
            INSERT INTO {h-schema}crl_entry (crl_uuid, serial_number, revocation_date, revocation_reason)
            VALUES (?1, ?2, ?3, ?4)
            ON CONFLICT (crl_uuid, serial_number)
            DO NOTHING
            """, nativeQuery = true)
    void insertWithIdConflictResolve(UUID crlUuid, String serialNumber, Date revocationDate, String revocationReason);

    @Modifying
    @Query(value = """
            INSERT INTO {h-schema}crl_entry (crl_uuid, serial_number, revocation_date, revocation_reason)
            VALUES (?1, ?2, ?3, ?4)
            ON CONFLICT (crl_uuid, serial_number)
            DO UPDATE SET revocation_date = EXCLUDED.revocation_date,
                          revocation_reason = EXCLUDED.revocation_reason
            """, nativeQuery = true)
    void upsertEntry(UUID crlUuid, String serialNumber, Date revocationDate, String revocationReason);

    @Modifying
    @Query("DELETE FROM CrlEntry e WHERE e.id.crlUuid = ?1 AND e.id.serialNumber = ?2")
    void deleteByCrlUuidAndSerialNumber(UUID crlUuid, String serialNumber);

    @Query("SELECT e FROM CrlEntry e WHERE e.id.crlUuid = ?1")
    List<CrlEntry> findAllByCrlUuid(UUID crlUuid);
}
