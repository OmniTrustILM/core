package com.otilm.core.dao.repository;

import com.otilm.core.dao.entity.TokenProfile;
import com.otilm.core.model.crypto.ImmutableTokenProfileBasicModel;
import com.otilm.core.model.crypto.ImmutableTokenProfileFullModel;
import com.otilm.core.model.crypto.TokenProfileFullModel;
import com.otilm.core.security.authz.SecurityFilter;
import jakarta.persistence.LockModeType;
import jakarta.persistence.criteria.CriteriaBuilder;
import jakarta.persistence.criteria.CriteriaQuery;
import jakarta.persistence.criteria.Root;
import java.util.List;
import java.util.Optional;
import java.util.UUID;
import org.springframework.data.jpa.repository.Lock;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

@Repository
public interface TokenProfileRepository extends SecurityFilterRepository<TokenProfile, UUID> {

    Optional<TokenProfile> findByUuid(UUID uuid);

    Optional<TokenProfile> findByName(String name);

    boolean existsByName(String name);

    @Query("""
            SELECT profile FROM TokenProfile profile
            JOIN FETCH profile.tokenInstanceReference token
            WHERE profile.uuid = :uuid
              AND profile.tokenInstanceReferenceUuid = :tokenUuid
            """)
    Optional<TokenProfile> findWithTokenInstanceByUuidAndTokenInstanceReferenceUuid(@Param("uuid") UUID uuid,
            @Param("tokenUuid") UUID tokenUuid);

    @Lock(LockModeType.PESSIMISTIC_WRITE)
    @Query("SELECT profile FROM TokenProfile profile WHERE profile.uuid = :uuid")
    Optional<TokenProfile> findWithLockByUuid(@Param("uuid") UUID uuid);

    @Lock(LockModeType.PESSIMISTIC_WRITE)
    @Query("SELECT profile FROM TokenProfile profile WHERE profile.uuid = :uuid AND profile.tokenInstanceReferenceUuid = :tokenUuid")
    Optional<TokenProfile> findWithLockByUuidAndTokenInstanceReferenceUuid(@Param("uuid") UUID uuid,
            @Param("tokenUuid") UUID tokenUuid);

    default Optional<ImmutableTokenProfileBasicModel> findBasicModelByUuid(UUID uuid) {
        return findByUuid(uuid).map(ImmutableTokenProfileBasicModel::from);
    }

    default Optional<TokenProfileFullModel> findFullModelByUuidAndTokenInstanceReferenceUuid(UUID uuid,
            UUID tokenUuid) {
        return findWithTokenInstanceByUuidAndTokenInstanceReferenceUuid(uuid, tokenUuid)
                .map(ImmutableTokenProfileFullModel::from);
    }

    default List<TokenProfileFullModel> findFullModelsUsingSecurityFilter(SecurityFilter filter) {
        return findUsingSecurityFilter(filter, List.of("tokenInstanceReference"), null)
                .stream()
                .<TokenProfileFullModel>map(ImmutableTokenProfileFullModel::from)
                .toList();
    }

    default List<TokenProfileFullModel> findFullModelsUsingSecurityFilter(SecurityFilter filter, boolean enabled) {
        return findUsingSecurityFilter(filter, List.of("tokenInstanceReference"),
                (Root<TokenProfile> root, CriteriaBuilder cb, CriteriaQuery<?> query) -> cb
                        .equal(root.get("enabled"), enabled))
                .stream()
                .<TokenProfileFullModel>map(ImmutableTokenProfileFullModel::from)
                .toList();
    }

}
