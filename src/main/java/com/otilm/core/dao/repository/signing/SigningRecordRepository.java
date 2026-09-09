package com.otilm.core.dao.repository.signing;

import com.otilm.core.dao.entity.signing.SigningRecord;
import com.otilm.core.dao.repository.SecurityFilterRepository;
import java.util.UUID;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import static com.otilm.core.dao.repository.signing.SigningRecordRollupSql.OPEN_VICTIM_CTE;
import static com.otilm.core.dao.repository.signing.SigningRecordRollupSql.ROLL_UP_THEN_DELETE;
import static com.otilm.core.dao.repository.signing.SigningRecordRollupSql.SKIP_CONTENDED_ROWS;
import static com.otilm.core.dao.repository.signing.SigningRecordRollupSql.WAIT_FOR_CONTENDED_ROWS;

/**
 * Every statement here that removes signing records rolls them into {@code signing_record_volume} first; see
 * {@link SigningRecordRollupSql}. They are native because a data-modifying CTE has no JPQL equivalent, and native
 * statements are opaque to Hibernate's auto-flush, hence {@code flushAutomatically}.
 */
@Repository
public interface SigningRecordRepository extends SecurityFilterRepository<SigningRecord, UUID> {
    boolean existsBySigningProfileUuidAndSigningProfileVersion(UUID signingProfileUuid, int version);

    boolean existsBySigningProfileUuid(UUID signingProfileUuid);

    @Modifying(flushAutomatically = true)
    @Query(value = OPEN_VICTIM_CTE + """
            SELECT sr.uuid, sr.signing_profile_uuid, sr.signing_time
            FROM {h-schema}signing_record sr
            WHERE sr.uuid = :uuid
            """ + WAIT_FOR_CONTENDED_ROWS + ROLL_UP_THEN_DELETE, nativeQuery = true)
    int deleteByUuid(@Param("uuid") UUID uuid);

    @Modifying(flushAutomatically = true)
    @Query(value = OPEN_VICTIM_CTE + """
            SELECT sr.uuid, sr.signing_profile_uuid, sr.signing_time
            FROM {h-schema}signing_record sr
            JOIN {h-schema}signing_profile_version spv
              ON sr.signing_profile_uuid = spv.signing_profile_uuid
             AND sr.signing_profile_version = spv.version
            WHERE spv.retention_days IS NOT NULL
              AND sr.signing_time < NOW() - make_interval(days => spv.retention_days)
            LIMIT :limit
            """ + SKIP_CONTENDED_ROWS + ROLL_UP_THEN_DELETE, nativeQuery = true)
    int deleteExpiredByRetention(@Param("limit") int limit);

    @Modifying(flushAutomatically = true)
    @Query(value = OPEN_VICTIM_CTE + """
            SELECT sr.uuid, sr.signing_profile_uuid, sr.signing_time
            FROM {h-schema}signing_record sr
            JOIN {h-schema}signing_profile_version spv
              ON sr.signing_profile_uuid = spv.signing_profile_uuid
             AND sr.signing_profile_version = spv.version
            WHERE spv.delete_after_retrieval = true
              AND sr.signed_document_retrieved_at IS NOT NULL
            LIMIT :limit
            """ + SKIP_CONTENDED_ROWS + ROLL_UP_THEN_DELETE, nativeQuery = true)
    int deleteRetrievedAndFlagged(@Param("limit") int limit);
}
