package com.otilm.core.dao.repository;

import com.otilm.api.exception.NotFoundException;
import com.otilm.api.model.common.NameAndUuidDto;
import com.otilm.api.model.core.scheduler.PaginationRequestDto;
import com.otilm.core.security.authz.SecuredUUID;
import com.otilm.core.security.authz.SecurityFilter;
import jakarta.persistence.criteria.CriteriaBuilder;
import jakarta.persistence.criteria.CriteriaDelete;
import jakarta.persistence.criteria.CriteriaQuery;
import jakarta.persistence.criteria.Expression;
import jakarta.persistence.criteria.Order;
import jakarta.persistence.criteria.Predicate;
import jakarta.persistence.criteria.Root;
import jakarta.persistence.metamodel.Attribute;
import jakarta.persistence.metamodel.SingularAttribute;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;
import java.util.function.BiFunction;
import org.apache.commons.lang3.function.TriFunction;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.repository.NoRepositoryBean;

@NoRepositoryBean
public interface SecurityFilterRepository<T, ID> extends JpaRepository<T, ID> {

    Optional<T> findByUuid(SecuredUUID uuid);

    Optional<T> findByUuid(SecuredUUID uuid, BiFunction<Root<T>, CriteriaBuilder, Predicate> additionalWhereClause);

    List<T> findUsingSecurityFilter(SecurityFilter filter);

    <R> List<R> findUsingSecurityFilter(SecurityFilter filter, Class<R> resultType,
            SecurityFilterProjection<T, R> projection);

    List<T> findUsingSecurityFilter(SecurityFilter filter, boolean enabled);

    List<T> findUsingSecurityFilter(SecurityFilter filter, List<String> fetchAssociations,
            TriFunction<Root<T>, CriteriaBuilder, CriteriaQuery<?>, Predicate> additionalWhereClause);

    List<T> findUsingSecurityFilter(SecurityFilter filter, List<String> fetchAssociations,
            TriFunction<Root<T>, CriteriaBuilder, CriteriaQuery<?>, Predicate> additionalWhereClause, Pageable p,
            BiFunction<Root<T>, CriteriaBuilder, Order> order);

    /**
     * Same, with the ordering the caller's request asked for. The {@code order} argument stays the ordering applied
     * when the request names none, so a caller that never supplies a sort keeps the order it has today.
     */
    List<T> findUsingSecurityFilter(SecurityFilter filter, List<String> fetchAssociations,
            TriFunction<Root<T>, CriteriaBuilder, CriteriaQuery<?>, Predicate> additionalWhereClause, Pageable p,
            BiFunction<Root<T>, CriteriaBuilder, Order> order, SortSpecification sort);

    List<UUID> findUuidsUsingSecurityFilter(SecurityFilter filter,
            TriFunction<Root<T>, CriteriaBuilder, CriteriaQuery<?>, Predicate> additionalWhereClause, Pageable p,
            BiFunction<Root<T>, CriteriaBuilder, Order> order);

    /**
     * Same, with the ordering the caller's request asked for. The returned list is ranked by that ordering, and the
     * rank is the only place it survives: a caller that loads the objects with a {@code uuid IN (...)} query gets them
     * in whatever order that query itself defines, so it has to put them back in the order of this list.
     */
    List<UUID> findUuidsUsingSecurityFilter(SecurityFilter filter,
            TriFunction<Root<T>, CriteriaBuilder, CriteriaQuery<?>, Predicate> additionalWhereClause, Pageable p,
            BiFunction<Root<T>, CriteriaBuilder, Order> order, SortSpecification sort);

    Map<String, Long> countGroupedUsingSecurityFilter(SecurityFilter filter, Attribute<?, ?> join,
            SingularAttribute<?, ?> groupBy, BiFunction<Root<T>, CriteriaBuilder, Expression<?>> groupByExpression,
            TriFunction<Root<T>, CriteriaBuilder, CriteriaQuery<?>, Predicate> additionalWhereClause);

    /**
     * Grouped total of an already-aggregated column, for entities whose rows each carry a count rather than being one.
     * {@code groupByExpression} is required here, where the grouped count above also accepts a join and attribute.
     * Unlike that count, this sum carries no DISTINCT: correct only where no predicate can duplicate the root row,
     * since a join that fans one row out multiplies the count that row carries.
     */
    Map<String, Long> sumGroupedUsingSecurityFilter(SecurityFilter filter, SingularAttribute<T, Long> sumOf,
            BiFunction<Root<T>, CriteriaBuilder, Expression<?>> groupByExpression,
            TriFunction<Root<T>, CriteriaBuilder, CriteriaQuery<?>, Predicate> additionalWhereClause);

    Long countUsingSecurityFilter(SecurityFilter filter);

    Long countUsingSecurityFilter(SecurityFilter filter,
            TriFunction<Root<T>, CriteriaBuilder, CriteriaQuery<?>, Predicate> additionalWhereClause);

    /**
     * Row count without the DISTINCT the variant above emits. Correct only where no predicate can duplicate the root
     * row: every joining shape must go through EXISTS subqueries and the resource's security filter must add no join of
     * its own. Where that holds, prefer this one -- Postgres cannot parallelize {@code count(DISTINCT ...)}, which at
     * millions of rows is seconds against milliseconds for a plain {@code count(*)}.
     */
    Long countRowsUsingSecurityFilter(SecurityFilter filter,
            TriFunction<Root<T>, CriteriaBuilder, CriteriaQuery<?>, Predicate> additionalWhereClause);

    Integer deleteUsingSecurityFilter(SecurityFilter filter,
            TriFunction<Root<T>, CriteriaBuilder, CriteriaDelete<T>, Predicate> additionalWhereClause);

    List<NameAndUuidDto> listResourceObjects(SecurityFilter securityFilter, SingularAttribute<T, String> nameAttribute);

    List<NameAndUuidDto> listResourceObjects(SecurityFilter securityFilter, SingularAttribute<T, String> nameAttribute,
            TriFunction<Root<T>, CriteriaBuilder, CriteriaQuery<?>, Predicate> additionalWhereClause);

    List<NameAndUuidDto> listResourceObjects(SecurityFilter securityFilter, SingularAttribute<T, String> nameAttribute,
            TriFunction<Root<T>, CriteriaBuilder, CriteriaQuery<?>, Predicate> additionalWhereClause,
            PaginationRequestDto page);

    List<NameAndUuidDto> listResourceObjects(SecurityFilter securityFilter,
            BiFunction<Root<T>, CriteriaBuilder, Expression<String>> nameExpressionFactory,
            TriFunction<Root<T>, CriteriaBuilder, CriteriaQuery<?>, Predicate> additionalWhereClause,
            PaginationRequestDto page);

    NameAndUuidDto findResourceObject(UUID uuid, SingularAttribute<T, String> nameAttribute) throws NotFoundException;

    NameAndUuidDto findResourceObject(UUID uuid,
            BiFunction<Root<T>, CriteriaBuilder, Expression<String>> nameExpressionFactory) throws NotFoundException;
}
