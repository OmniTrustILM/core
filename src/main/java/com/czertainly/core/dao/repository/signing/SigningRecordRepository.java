package com.czertainly.core.dao.repository.signing;

import com.czertainly.core.dao.entity.signing.SigningRecord;
import com.czertainly.core.dao.repository.SecurityFilterRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.UUID;

@Repository
public interface SigningRecordRepository extends SecurityFilterRepository<SigningRecord, UUID> {
    boolean existsBySigningProfileUuidAndSigningProfileVersion(UUID signingProfileUuid, int version);

    List<SigningRecord> findAllBySigningProfileUuid(UUID signingProfileUuid);

    @Modifying
    @Query(value = """
            DELETE FROM {h-schema}signing_record sr
            USING {h-schema}signing_profile sp
            WHERE sr.signing_profile_uuid = sp.uuid
              AND sp.retention_days IS NOT NULL
              AND sr.created_at < NOW() - (sp.retention_days || ' days')::interval
            """, nativeQuery = true)
    int deleteExpiredByRetention();

    @Modifying
    @Query(value = """
            DELETE FROM {h-schema}signing_record sr
            USING {h-schema}signing_profile sp
            WHERE sr.signing_profile_uuid = sp.uuid
              AND sp.delete_after_retrieval = true
              AND sr.signed_document_retrieved_at IS NOT NULL
            """, nativeQuery = true)
    int deleteRetrievedAndFlagged();

    @Query(value = "SELECT pg_try_advisory_lock(:key)", nativeQuery = true)
    boolean tryAdvisoryLock(@Param("key") long key);

    @Query(value = "SELECT pg_advisory_unlock(:key)", nativeQuery = true)
    boolean releaseAdvisoryLock(@Param("key") long key);
}
