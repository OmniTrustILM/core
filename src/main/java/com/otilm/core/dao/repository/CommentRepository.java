package com.otilm.core.dao.repository;

import com.otilm.api.model.core.auth.Resource;
import com.otilm.core.dao.entity.Comment;
import java.time.OffsetDateTime;
import java.util.Collection;
import java.util.List;
import java.util.Optional;
import java.util.UUID;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.domain.Sort;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

@Repository
public interface CommentRepository extends SecurityFilterRepository<Comment, UUID> {

    /**
     * Unordered unless the {@code Pageable} carries a {@link Sort}. Paging a comment listing without one walks rows in
     * storage order, which shifts under writes and can repeat or drop a row across pages.
     */
    Page<Comment> findByResourceAndObjectUuidAndParentUuidIsNull(Resource resource, UUID objectUuid, Pageable pageable);

    /**
     * Unordered unless the {@code Pageable} carries a {@link Sort}, as for
     * {@link #findByResourceAndObjectUuidAndParentUuidIsNull}.
     */
    Page<Comment> findByParentUuid(UUID parentUuid, Pageable pageable);

    // Locked like the root (see findWithLockByUuid), so a reply deleted by a concurrent request is not reported as
    // removed by the cascade: that request waits and then finds nothing.
    @Query(value = "SELECT * FROM {h-schema}comment WHERE parent_uuid = :parentUuid ORDER BY created_at, uuid"
            + " FOR UPDATE", nativeQuery = true)
    List<Comment> findRepliesWithLockByParentUuid(@Param("parentUuid") UUID parentUuid);

    // Position of a comment within its listing, so a caller anchored at one can be given the page holding it: the
    // comments sorted ahead of it are those created before it when the listing ascends and after it when it descends.
    // The predicates mirror the listing order, uuid tie-break included, and run in the database so its uuid ordering
    // is the one used throughout.
    @Query("SELECT COUNT(c) FROM Comment c WHERE c.resource = :resource AND c.objectUuid = :objectUuid"
            + " AND c.parentUuid IS NULL"
            + " AND (c.createdAt < :createdAt OR (c.createdAt = :createdAt AND c.uuid < :uuid))")
    long countRootsCreatedBefore(@Param("resource") Resource resource, @Param("objectUuid") UUID objectUuid,
            @Param("createdAt") OffsetDateTime createdAt, @Param("uuid") UUID uuid);

    @Query("SELECT COUNT(c) FROM Comment c WHERE c.resource = :resource AND c.objectUuid = :objectUuid"
            + " AND c.parentUuid IS NULL"
            + " AND (c.createdAt > :createdAt OR (c.createdAt = :createdAt AND c.uuid > :uuid))")
    long countRootsCreatedAfter(@Param("resource") Resource resource, @Param("objectUuid") UUID objectUuid,
            @Param("createdAt") OffsetDateTime createdAt, @Param("uuid") UUID uuid);

    @Query("SELECT COUNT(c) FROM Comment c WHERE c.parentUuid = :parentUuid"
            + " AND (c.createdAt < :createdAt OR (c.createdAt = :createdAt AND c.uuid < :uuid))")
    long countRepliesCreatedBefore(@Param("parentUuid") UUID parentUuid, @Param("createdAt") OffsetDateTime createdAt,
            @Param("uuid") UUID uuid);

    @Query("SELECT COUNT(c) FROM Comment c WHERE c.parentUuid = :parentUuid"
            + " AND (c.createdAt > :createdAt OR (c.createdAt = :createdAt AND c.uuid > :uuid))")
    long countRepliesCreatedAfter(@Param("parentUuid") UUID parentUuid, @Param("createdAt") OffsetDateTime createdAt,
            @Param("uuid") UUID uuid);

    @Query("SELECT c.parentUuid, COUNT(c) FROM Comment c WHERE c.parentUuid IN :rootUuids GROUP BY c.parentUuid")
    List<Object[]> countRepliesByRoots(@Param("rootUuids") Collection<UUID> rootUuids);

    boolean existsByParentUuidAndAuthorUuidNot(UUID parentUuid, UUID authorUuid);

    boolean existsByResourceAndObjectUuid(Resource resource, UUID objectUuid);

    // Spelled out because Hibernate renders a pessimistic write lock as FOR NO KEY UPDATE on PostgreSQL, which does
    // not conflict with the key-share lock a reply's insert holds on its parent row; only FOR UPDATE does.
    @Query(value = "SELECT * FROM {h-schema}comment WHERE uuid = :uuid FOR UPDATE", nativeQuery = true)
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
