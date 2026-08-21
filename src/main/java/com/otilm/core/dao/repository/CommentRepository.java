package com.otilm.core.dao.repository;

import com.otilm.api.model.core.auth.Resource;
import com.otilm.core.dao.entity.Comment;
import jakarta.persistence.LockModeType;
import java.time.OffsetDateTime;
import java.util.Collection;
import java.util.List;
import java.util.Optional;
import java.util.UUID;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.Lock;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

@Repository
public interface CommentRepository extends SecurityFilterRepository<Comment, UUID> {

    Page<Comment> findByResourceAndObjectUuidAndParentUuidIsNullOrderByCreatedAtAsc(Resource resource, UUID objectUuid,
            Pageable pageable);

    Page<Comment> findByParentUuidOrderByCreatedAtAsc(UUID parentUuid, Pageable pageable);

    @Query("SELECT c.parentUuid, COUNT(c) FROM Comment c WHERE c.parentUuid IN :rootUuids GROUP BY c.parentUuid")
    List<Object[]> countRepliesByRoots(@Param("rootUuids") Collection<UUID> rootUuids);

    boolean existsByParentUuid(UUID parentUuid);

    boolean existsByResourceAndObjectUuid(Resource resource, UUID objectUuid);

    @Lock(LockModeType.PESSIMISTIC_WRITE)
    @Query("SELECT c FROM Comment c WHERE c.uuid = :uuid")
    Optional<Comment> findWithLockByUuid(@Param("uuid") UUID uuid);

    @Query("SELECT DISTINCT c.authorUuid FROM Comment c WHERE c.uuid = :rootUuid OR c.parentUuid = :rootUuid")
    List<UUID> findThreadParticipantUuids(@Param("rootUuid") UUID rootUuid);

    // The state predicate makes the transition atomic: a repeated request updates no rows, so the caller can
    // tell a real transition from a no-op without reading the row first.
    @Modifying
    @Query("UPDATE Comment c SET c.resolvedAt = :resolvedAt, c.resolvedByUuid = :actorUuid, "
            + "c.resolvedByUsername = :actorUsername WHERE c.uuid = :uuid AND c.resolvedAt IS NULL")
    int resolve(@Param("uuid") UUID uuid, @Param("resolvedAt") OffsetDateTime resolvedAt,
            @Param("actorUuid") UUID actorUuid, @Param("actorUsername") String actorUsername);

    @Modifying
    @Query("UPDATE Comment c SET c.resolvedAt = NULL, c.resolvedByUuid = NULL, c.resolvedByUsername = NULL "
            + "WHERE c.uuid = :uuid AND c.resolvedAt IS NOT NULL")
    int unresolve(@Param("uuid") UUID uuid);

    @Modifying
    @Query("DELETE FROM Comment c WHERE c.uuid = :uuid")
    int deleteCommentByUuid(@Param("uuid") UUID uuid);

    @Modifying
    @Query("DELETE FROM Comment c WHERE c.resource = :resource AND c.objectUuid = :objectUuid")
    int deleteAllByResourceAndObjectUuid(@Param("resource") Resource resource, @Param("objectUuid") UUID objectUuid);
}
