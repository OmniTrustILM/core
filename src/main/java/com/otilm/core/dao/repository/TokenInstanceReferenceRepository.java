package com.otilm.core.dao.repository;

import com.otilm.core.dao.entity.TokenInstanceReference;
import com.otilm.core.dao.entity.TokenInstanceReference_;
import com.otilm.core.dao.entity.TokenProfile;
import com.otilm.core.dao.entity.UniquelyIdentifiedAndAudited_;
import com.otilm.core.model.crypto.ImmutableTokenInstanceBasicModel;
import com.otilm.core.model.crypto.ImmutableTokenInstanceFullModel;
import com.otilm.core.model.crypto.TokenInstanceBasicModel;
import com.otilm.core.model.crypto.TokenInstanceFullModel;
import com.otilm.core.security.authz.SecurityFilter;
import jakarta.persistence.LockModeType;
import jakarta.persistence.criteria.Expression;
import jakarta.persistence.criteria.Join;
import jakarta.persistence.criteria.JoinType;
import jakarta.persistence.criteria.Selection;
import java.util.List;
import java.util.Optional;
import java.util.UUID;
import org.springframework.data.jpa.repository.EntityGraph;
import org.springframework.data.jpa.repository.Lock;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

@Repository
public interface TokenInstanceReferenceRepository extends SecurityFilterRepository<TokenInstanceReference, UUID> {

    Optional<TokenInstanceReference> findByUuid(UUID uuid);

    /**
     * Loads an existing token instance for a read-modify-write operation. The lock must be acquired inside the
     * transaction that performs the update.
     */
    @Lock(LockModeType.PESSIMISTIC_WRITE)
    @Query("SELECT token FROM TokenInstanceReference token WHERE token.uuid = :uuid")
    Optional<TokenInstanceReference> findWithLockByUuid(@Param("uuid") UUID uuid);

    boolean existsByUuid(UUID uuid);

    Optional<TokenInstanceReference> findByName(String name);

    boolean existsByName(String name);

    @Query("""
            SELECT new com.otilm.core.model.crypto.ImmutableTokenInstanceBasicModel(
                token.uuid, token.tokenInstanceUuid, token.name, token.status, token.kind,
                token.connectorUuid, token.connectorName, token.connectorInterfaceUuid,
                count(DISTINCT profile.uuid))
            FROM TokenInstanceReference token
            LEFT JOIN token.tokenProfiles profile
            WHERE token.uuid = :uuid
            GROUP BY token.uuid, token.tokenInstanceUuid, token.name, token.status, token.kind,
                token.connectorUuid, token.connectorName, token.connectorInterfaceUuid
            """)
    Optional<TokenInstanceBasicModel> findBasicModelByUuid(@Param("uuid") UUID uuid);

    @EntityGraph(attributePaths = {"connector", "connectorInterface", "tokenProfiles"})
    @Query("SELECT token FROM TokenInstanceReference token WHERE token.uuid = :uuid")
    Optional<TokenInstanceReference> findWithAssociationsByUuid(@Param("uuid") UUID uuid);

    default Optional<TokenInstanceFullModel> findFullModelByUuid(UUID uuid) {
        return findWithAssociationsByUuid(uuid).map(ImmutableTokenInstanceFullModel::from);
    }

    default List<TokenInstanceBasicModel> findBasicModelsUsingSecurityFilter(SecurityFilter filter) {
        return findUsingSecurityFilter(filter, ImmutableTokenInstanceBasicModel.class, (root, cb) -> {
            Join<TokenInstanceReference, TokenProfile> profiles = root
                    .join(TokenInstanceReference_.tokenProfiles, JoinType.LEFT);

            Selection<ImmutableTokenInstanceBasicModel> selection = cb
                    .construct(ImmutableTokenInstanceBasicModel.class, root.get(UniquelyIdentifiedAndAudited_.uuid),
                            root.get(TokenInstanceReference_.tokenInstanceUuid), root.get(TokenInstanceReference_.name),
                            root.get(TokenInstanceReference_.status), root.get(TokenInstanceReference_.kind),
                            root.get(TokenInstanceReference_.connectorUuid),
                            root.get(TokenInstanceReference_.connectorName),
                            root.get(TokenInstanceReference_.connectorInterfaceUuid),
                            cb.countDistinct(profiles.get(UniquelyIdentifiedAndAudited_.uuid)));

            List<Expression<?>> groupByExpressions = List
                    .of(root.get(UniquelyIdentifiedAndAudited_.uuid),
                            root.get(TokenInstanceReference_.tokenInstanceUuid), root.get(TokenInstanceReference_.name),
                            root.get(TokenInstanceReference_.status), root.get(TokenInstanceReference_.kind),
                            root.get(TokenInstanceReference_.connectorUuid),
                            root.get(TokenInstanceReference_.connectorName),
                            root.get(TokenInstanceReference_.connectorInterfaceUuid));

            return new SecurityFilterProjectionSpec<>(selection, groupByExpressions);
        }).stream().map(value -> (TokenInstanceBasicModel) value).toList();
    }

}
