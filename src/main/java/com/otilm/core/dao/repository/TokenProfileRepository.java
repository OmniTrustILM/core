package com.otilm.core.dao.repository;

import com.otilm.core.dao.entity.TokenProfile;
import com.otilm.core.model.crypto.ImmutableTokenProfileBasicModel;
import com.otilm.core.model.crypto.ImmutableTokenProfileFullModel;
import com.otilm.core.model.crypto.ImmutableTokenProfileListModel;
import com.otilm.core.model.crypto.TokenInstanceFullModel;
import com.otilm.core.model.crypto.TokenProfileFullModel;
import com.otilm.core.model.crypto.TokenProfileListModel;
import com.otilm.core.security.authz.SecurityFilter;
import jakarta.persistence.LockModeType;
import jakarta.persistence.criteria.CriteriaBuilder;
import jakarta.persistence.criteria.CriteriaQuery;
import jakarta.persistence.criteria.Root;
import java.util.List;
import java.util.Optional;
import java.util.UUID;
import org.springframework.data.jpa.repository.EntityGraph;
import org.springframework.data.jpa.repository.Lock;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

@Repository
public interface TokenProfileRepository extends SecurityFilterRepository<TokenProfile, UUID> {

    Optional<TokenProfile> findByUuid(UUID uuid);

    Optional<TokenProfile> findByName(String name);

    boolean existsByName(String name);

    List<TokenProfile> findByTokenInstanceReferenceUuid(UUID tokenInstanceReferenceUuid);

    @EntityGraph(attributePaths = {"tokenInstanceReference.connectorInterface", "tokenInstanceReference.tokenProfiles"})
    @Query("""
            SELECT profile FROM TokenProfile profile
            JOIN FETCH profile.tokenInstanceReference token
            WHERE profile.uuid = :uuid
              AND profile.tokenInstanceReferenceUuid = :tokenUuid
            """)
    Optional<TokenProfile> findWithTokenInstanceByUuidAndTokenInstanceReferenceUuid(@Param("uuid") UUID uuid,
            @Param("tokenUuid") UUID tokenUuid);

    @Lock(LockModeType.PESSIMISTIC_WRITE)
    @Query("SELECT profile FROM TokenProfile profile WHERE profile.tokenInstanceReferenceUuid = :tokenUuid ORDER BY profile.uuid")
    List<TokenProfile> findWithLockByTokenInstanceReferenceUuid(@Param("tokenUuid") UUID tokenUuid);

    @Lock(LockModeType.PESSIMISTIC_WRITE)
    @Query("""
            SELECT profile FROM TokenProfile profile
            WHERE profile.tokenInstanceReferenceUuid IN (
                SELECT token.uuid FROM TokenInstanceReference token WHERE token.connectorUuid = :connectorUuid)
            ORDER BY profile.uuid
            """)
    List<TokenProfile> findWithLockByConnectorUuid(@Param("connectorUuid") UUID connectorUuid);

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

    /** The token's profiles, sharing the one snapshot of the token given. */
    default List<TokenProfileFullModel> findFullModelsByTokenInstance(TokenInstanceFullModel token) {
        return findByTokenInstanceReferenceUuid(token.uuid())
                .stream()
                .<TokenProfileFullModel>map(profile -> ImmutableTokenProfileFullModel.from(profile, token))
                .toList();
    }

    default List<TokenProfileListModel> findListModelsUsingSecurityFilter(SecurityFilter filter) {
        return findUsingSecurityFilter(filter, List.of("tokenInstanceReference"), null)
                .stream()
                .<TokenProfileListModel>map(ImmutableTokenProfileListModel::from)
                .toList();
    }

    default List<TokenProfileListModel> findListModelsUsingSecurityFilter(SecurityFilter filter, boolean enabled) {
        return findUsingSecurityFilter(filter, List.of("tokenInstanceReference"),
                (Root<TokenProfile> root, CriteriaBuilder cb, CriteriaQuery<?> query) -> cb
                        .equal(root.get("enabled"), enabled))
                .stream()
                .<TokenProfileListModel>map(ImmutableTokenProfileListModel::from)
                .toList();
    }

}
