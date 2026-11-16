package com.otilm.core.dao.repository;

import com.otilm.core.dao.entity.CrlEntry;
import com.otilm.core.dao.entity.CrlEntryId;
import java.util.Optional;
import java.util.UUID;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.stereotype.Repository;

@Repository
public interface CrlEntryRepository extends SecurityFilterRepository<CrlEntry, Long> {

    Optional<CrlEntry> findById(CrlEntryId id);

    /** Deletes the entries in one statement, without loading them as a derived delete would. */
    @Modifying
    @Query("DELETE FROM CrlEntry e WHERE e.id.crlUuid = ?1")
    void deleteEntriesOfCrl(UUID crlUuid);
}
