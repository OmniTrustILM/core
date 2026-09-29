package com.otilm.core.dao.repository;

import com.otilm.api.model.core.auth.Resource;
import com.otilm.core.dao.entity.ListView;
import java.util.List;
import java.util.Optional;
import java.util.UUID;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

/**
 * Views are private to the user who saved them, so every finder is keyed by the user UUID rather than routed through
 * the secured-search repository: there is no object-level permission to evaluate, and no view is addressable by anyone
 * else.
 */
@Repository
public interface ListViewRepository extends JpaRepository<ListView, UUID> {

    List<ListView> findByUserUuidOrderByCreatedAscUuidAsc(UUID userUuid);

    List<ListView> findByUserUuidAndResourceOrderByCreatedAscUuidAsc(UUID userUuid, Resource resource);

    Optional<ListView> findByUuidAndUserUuid(UUID uuid, UUID userUuid);

    boolean existsByUserUuidAndResourceAndName(UUID userUuid, Resource resource, String name);

    boolean existsByUserUuidAndResourceAndNameAndUuidNot(UUID userUuid, Resource resource, String name, UUID uuid);

    @Modifying
    @Query("UPDATE ListView v SET v.defaultView = FALSE, v.updated = CURRENT_TIMESTAMP "
            + "WHERE v.userUuid = :userUuid AND v.resource = :resource AND v.defaultView = TRUE "
            + "AND v.uuid <> :keptUuid")
    int clearDefaultExcept(@Param("userUuid") UUID userUuid, @Param("resource") Resource resource,
            @Param("keptUuid") UUID keptUuid);

    @Modifying
    @Query("DELETE FROM ListView v WHERE v.userUuid = :userUuid")
    int deleteByUserUuid(@Param("userUuid") UUID userUuid);
}
