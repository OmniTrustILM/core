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

    boolean existsBySigningProfileUuid(UUID signingProfileUuid);

    @Modifying
    @Query("DELETE FROM SigningRecord sr WHERE sr.uuid = :uuid")
    int deleteByUuid(@Param("uuid") UUID uuid);

    @Modifying
    @Query(value = """
            DELETE FROM {h-schema}signing_record
            WHERE ctid IN (
                SELECT sr.ctid
                FROM {h-schema}signing_record sr
                JOIN {h-schema}signing_profile_version spv
                  ON sr.signing_profile_uuid = spv.signing_profile_uuid
                 AND sr.signing_profile_version = spv.version
                WHERE spv.retention_days IS NOT NULL
                  AND sr.signing_time < NOW() - make_interval(days => spv.retention_days)
                LIMIT :limit
            )
            """, nativeQuery = true)
    int deleteExpiredByRetention(@Param("limit") int limit);

    @Modifying
    @Query(value = """
            DELETE FROM {h-schema}signing_record
            WHERE ctid IN (
                SELECT sr.ctid
                FROM {h-schema}signing_record sr
                JOIN {h-schema}signing_profile_version spv
                  ON sr.signing_profile_uuid = spv.signing_profile_uuid
                 AND sr.signing_profile_version = spv.version
                WHERE spv.delete_after_retrieval = true
                  AND sr.signed_document_retrieved_at IS NOT NULL
                LIMIT :limit
            )
            """, nativeQuery = true)
    int deleteRetrievedAndFlagged(@Param("limit") int limit);
}
