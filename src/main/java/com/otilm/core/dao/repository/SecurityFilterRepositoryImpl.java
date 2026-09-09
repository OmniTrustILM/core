package com.otilm.core.dao.repository;

import com.otilm.api.exception.NotFoundException;
import com.otilm.api.exception.ValidationError;
import com.otilm.api.exception.ValidationException;
import com.otilm.api.model.common.NameAndUuidDto;
import com.otilm.api.model.core.scheduler.PaginationRequestDto;
import com.otilm.core.dao.AggregateResultDto;
import com.otilm.core.dao.entity.CryptographicKeyItem;
import com.otilm.core.dao.entity.CryptographicKeyItem_;
import com.otilm.core.dao.entity.UniquelyIdentifiedObject;
import com.otilm.core.dao.entity.UniquelyIdentified_;
import com.otilm.core.model.auth.ResourceAction;
import com.otilm.core.security.authz.SecuredUUID;
import com.otilm.core.security.authz.SecurityFilter;
import com.otilm.core.security.authz.SecurityResourceFilter;
import com.otilm.core.util.AuthHelper;
import com.otilm.core.util.FilterPredicatesBuilder;
import com.otilm.core.util.SortOrderBuilder;
import jakarta.persistence.EntityManager;
import jakarta.persistence.NoResultException;
import jakarta.persistence.Tuple;
import jakarta.persistence.TypedQuery;
import jakarta.persistence.criteria.CommonAbstractCriteria;
import jakarta.persistence.criteria.CriteriaBuilder;
import jakarta.persistence.criteria.CriteriaDelete;
import jakarta.persistence.criteria.CriteriaQuery;
import jakarta.persistence.criteria.Expression;
import jakarta.persistence.criteria.FetchParent;
import jakarta.persistence.criteria.From;
import jakarta.persistence.criteria.Join;
import jakarta.persistence.criteria.JoinType;
import jakarta.persistence.criteria.Order;
import jakarta.persistence.criteria.Path;
import jakarta.persistence.criteria.Predicate;
import jakarta.persistence.criteria.Root;
import jakarta.persistence.metamodel.Attribute;
import jakarta.persistence.metamodel.SingularAttribute;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.StringTokenizer;
import java.util.UUID;
import java.util.function.BiFunction;
import java.util.stream.Collectors;
import org.apache.commons.lang3.function.TriFunction;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.support.JpaEntityInformation;
import org.springframework.data.jpa.repository.support.SimpleJpaRepository;

public class SecurityFilterRepositoryImpl<T, ID> extends SimpleJpaRepository<T, ID>
        implements
            SecurityFilterRepository<T, ID> {

    private final JpaEntityInformation<T, ?> entityInformation;
    private final EntityManager entityManager;

    public SecurityFilterRepositoryImpl(JpaEntityInformation<T, ?> entityInformation, EntityManager entityManager) {
        super(entityInformation, entityManager);
        this.entityInformation = entityInformation;
        this.entityManager = entityManager;
    }

    public Optional<T> findByUuid(SecuredUUID uuid) {
        return findByUuid(uuid, null);
    }

    @Override
    public Optional<T> findByUuid(SecuredUUID uuid,
            BiFunction<Root<T>, CriteriaBuilder, Predicate> additionalWhereClause) {
        try {
            Class<T> entity = this.entityInformation.getJavaType();
            CriteriaBuilder cb = entityManager.getCriteriaBuilder();
            CriteriaQuery<T> cr = cb.createQuery(entity);
            Root<T> root = cr.from(entity);
            List<Predicate> predicates = new ArrayList<>();
            predicates.add(cb.equal(root.get("uuid"), uuid.getValue()));

            if (additionalWhereClause != null) {
                predicates.add(additionalWhereClause.apply(root, cb));
            }
            cr.select(root).where(predicates.toArray(new Predicate[]{}));
            T result = entityManager.createQuery(cr).getSingleResult();
            return Optional.of(result);
        } catch (NoResultException e) {
            return Optional.empty();
        }
    }

    @Override
    public List<T> findUsingSecurityFilter(SecurityFilter filter) {
        return this.findUsingSecurityFilter(filter, List.of(), null);
    }

    @Override
    public <R> List<R> findUsingSecurityFilter(SecurityFilter filter, Class<R> resultType,
            SecurityFilterProjection<T, R> projection) {
        CriteriaBuilder cb = entityManager.getCriteriaBuilder();
        CriteriaQuery<R> cr = cb.createQuery(resultType);
        Root<T> root = cr.from(entityInformation.getJavaType());

        SecurityFilterProjectionSpec<R> projectionSpec = projection.create(root, cb);
        cr.select(projectionSpec.selection());
        cr.groupBy(projectionSpec.groupByExpressions());

        List<Predicate> predicates = getPredicates(filter, null, root, cb);
        if (!predicates.isEmpty()) {
            cr.where(predicates.toArray(Predicate[]::new));
        }
        return entityManager.createQuery(cr).getResultList();
    }

    @Override
    public List<T> findUsingSecurityFilter(SecurityFilter filter, boolean enabled) {
        return findUsingSecurityFilter(filter, List.of(), (root, cb, cr) -> cb.equal(root.get("enabled"), enabled));
    }

    @Override
    public List<T> findUsingSecurityFilter(SecurityFilter filter, List<String> fetchAssociations,
            TriFunction<Root<T>, CriteriaBuilder, CriteriaQuery<?>, Predicate> additionalWhereClause) {
        final CriteriaQuery<T> cr = createCriteriaBuilder(filter, fetchAssociations, additionalWhereClause, null);
        return entityManager.createQuery(cr).getResultList();
    }

    @Override
    public List<T> findUsingSecurityFilter(final SecurityFilter filter, List<String> fetchAssociations,
            final TriFunction<Root<T>, CriteriaBuilder, CriteriaQuery<?>, Predicate> additionalWhereClause,
            final Pageable p, final BiFunction<Root<T>, CriteriaBuilder, Order> order) {
        return findUsingSecurityFilter(filter, fetchAssociations, additionalWhereClause, p, order, null);
    }

    @Override
    public List<T> findUsingSecurityFilter(final SecurityFilter filter, List<String> fetchAssociations,
            final TriFunction<Root<T>, CriteriaBuilder, CriteriaQuery<?>, Predicate> additionalWhereClause,
            final Pageable p, final BiFunction<Root<T>, CriteriaBuilder, Order> order, final SortSpecification sort) {
        if (SortOrderBuilder.needsRankedUuidQuery(sort)) {
            return loadInUuidOrder(findUuidsOrderedBySortKey(filter, additionalWhereClause, p, sort),
                    fetchAssociations);
        }
        final CriteriaQuery<T> cr = createCriteriaBuilder(filter, fetchAssociations, additionalWhereClause, order, sort,
                p != null);
        return window(entityManager.createQuery(cr), p).getResultList();
    }

    @Override
    public List<UUID> findUuidsUsingSecurityFilter(final SecurityFilter filter,
            final TriFunction<Root<T>, CriteriaBuilder, CriteriaQuery<?>, Predicate> additionalWhereClause,
            final Pageable p, final BiFunction<Root<T>, CriteriaBuilder, Order> order) {
        return findUuidsUsingSecurityFilter(filter, additionalWhereClause, p, order, null);
    }

    @Override
    public List<UUID> findUuidsUsingSecurityFilter(final SecurityFilter filter,
            final TriFunction<Root<T>, CriteriaBuilder, CriteriaQuery<?>, Predicate> additionalWhereClause,
            final Pageable p, final BiFunction<Root<T>, CriteriaBuilder, Order> order, final SortSpecification sort) {
        if (SortOrderBuilder.needsRankedUuidQuery(sort)) {
            return findUuidsOrderedBySortKey(filter, additionalWhereClause, p, sort);
        }
        final CriteriaQuery<UUID> cr = createCriteriaBuilderUuid(filter, additionalWhereClause, order, sort, p != null);
        return window(entityManager.createQuery(cr), p).getResultList();
    }

    /**
     * The uuids of a page in the order the request asked for, for the two sorts the entity query cannot carry itself.
     *
     * <p>
     * A sort through a join gives a root as many rows as the join has matches, so a window cut over those rows would
     * underfill the page and let the same root reappear on the next one. A sort by an attribute resolves to a
     * correlated scalar subquery, and the entity query selects DISTINCT, which the database will not order by an
     * expression that is absent from the select list.
     *
     * <p>
     * This query answers both: it selects the sort key alongside the uuid, groups by the uuid and orders by the
     * aggregate the ordering resolves - one row per root, carrying its key, which is what the window is allowed to cut.
     */
    private List<UUID> findUuidsOrderedBySortKey(final SecurityFilter filter,
            final TriFunction<Root<T>, CriteriaBuilder, CriteriaQuery<?>, Predicate> additionalWhereClause,
            final Pageable p, final SortSpecification sort) {
        final Class<T> entity = this.entityInformation.getJavaType();
        final CriteriaBuilder cb = entityManager.getCriteriaBuilder();
        final CriteriaQuery<Tuple> cr = cb.createTupleQuery();
        final Root<T> root = cr.from(entity);
        final Path<?> uuid = root.get(UniquelyIdentified_.UUID);

        final SortOrderBuilder.GroupedOrdering ordering = SortOrderBuilder.resolveGrouped(root, cb, cr, sort);
        cr.multiselect(uuid, ordering.sortKey());
        cr.groupBy(uuid);
        cr.orderBy(ordering.orders());
        applyPredicates(cr, filter, additionalWhereClause, root, cb);

        return window(entityManager.createQuery(cr), p)
                .getResultList()
                .stream()
                .map(tuple -> tuple.get(0, UUID.class))
                .toList();
    }

    /**
     * Loads the entities a page of uuids names, in the order the page ranks them. A plural fetch association repeats a
     * root across the rows it returns, and the database is free to return them in any order, so the ranking the page
     * carries is what the result is rebuilt from.
     */
    private List<T> loadInUuidOrder(final List<UUID> uuids, final List<String> fetchAssociations) {
        if (uuids.isEmpty()) {
            return List.of();
        }
        final Class<T> entity = this.entityInformation.getJavaType();
        final CriteriaBuilder cb = entityManager.getCriteriaBuilder();
        final CriteriaQuery<T> cr = cb.createQuery(entity);
        final Root<T> root = cr.from(entity);

        fetchAssociations(root, fetchAssociations);
        cr.select(root).where(root.get(UniquelyIdentified_.UUID).in(uuids));

        final Map<UUID, T> byUuid = new HashMap<>();
        for (T loaded : entityManager.createQuery(cr).getResultList()) {
            if (loaded instanceof UniquelyIdentifiedObject identified) {
                byUuid.putIfAbsent(identified.getUuid(), loaded);
            }
        }
        return uuids.stream().map(byUuid::get).filter(Objects::nonNull).toList();
    }

    private List<Order> resolveOrdering(final Root<T> root, final CriteriaBuilder cb,
            final CommonAbstractCriteria query, final BiFunction<Root<T>, CriteriaBuilder, Order> order,
            final SortSpecification sort, final boolean paged) {
        final Order defaultOrder = order == null ? null : order.apply(root, cb);
        return SortOrderBuilder.resolve(root, cb, query, sort, defaultOrder, paged);
    }

    private void applyPredicates(final CriteriaQuery<?> cr, final SecurityFilter filter,
            final TriFunction<Root<T>, CriteriaBuilder, CriteriaQuery<?>, Predicate> additionalWhereClause,
            final Root<T> root, final CriteriaBuilder cb) {
        final List<Predicate> predicates = getPredicates(filter, additionalWhereClause, root, cb, cr);
        if (!predicates.isEmpty()) {
            cr.where(predicates.toArray(new Predicate[]{}));
        }
    }

    private <R> TypedQuery<R> window(final TypedQuery<R> query, final Pageable p) {
        if (p != null) {
            query.setFirstResult((int) p.getOffset()).setMaxResults(p.getPageSize());
        }
        return query;
    }

    @Override
    public Map<String, Long> countGroupedUsingSecurityFilter(SecurityFilter filter, Attribute<?, ?> join,
            SingularAttribute<?, ?> groupBy, BiFunction<Root<T>, CriteriaBuilder, Expression<?>> groupByExpression,
            TriFunction<Root<T>, CriteriaBuilder, CriteriaQuery<?>, Predicate> additionalWhereClause) {
        BiFunction<Root<T>, CriteriaBuilder, Expression<?>> grouping = groupByExpression != null
                ? groupByExpression
                : groupingByAttribute(join, groupBy);
        return aggregateGroupedUsingSecurityFilter(filter, grouping, (root, cb) -> cb.countDistinct(root),
                additionalWhereClause);
    }

    /** Groups by {@code groupBy}, read off the root or off a left join to {@code join} when one is given. */
    private BiFunction<Root<T>, CriteriaBuilder, Expression<?>> groupingByAttribute(Attribute<?, ?> join,
            SingularAttribute<?, ?> groupBy) {
        return (root, cb) -> {
            From<?, ?> from = join == null ? root : root.join(join.getName(), JoinType.LEFT);
            return from.get(groupBy.getName());
        };
    }

    @Override
    public Map<String, Long> sumGroupedUsingSecurityFilter(SecurityFilter filter, SingularAttribute<T, Long> sumOf,
            BiFunction<Root<T>, CriteriaBuilder, Expression<?>> groupByExpression,
            TriFunction<Root<T>, CriteriaBuilder, CriteriaQuery<?>, Predicate> additionalWhereClause) {
        Objects.requireNonNull(groupByExpression, "groupByExpression");
        return aggregateGroupedUsingSecurityFilter(filter, groupByExpression, (root, cb) -> cb.sum(root.get(sumOf)),
                additionalWhereClause);
    }

    private Map<String, Long> aggregateGroupedUsingSecurityFilter(SecurityFilter filter,
            BiFunction<Root<T>, CriteriaBuilder, Expression<?>> groupByExpression,
            BiFunction<Root<T>, CriteriaBuilder, Expression<? extends Number>> aggregation,
            TriFunction<Root<T>, CriteriaBuilder, CriteriaQuery<?>, Predicate> additionalWhereClause) {
        final Class<T> entity = this.entityInformation.getJavaType();
        final CriteriaBuilder cb = entityManager.getCriteriaBuilder();
        CriteriaQuery<AggregateResultDto> cr = cb.createQuery(AggregateResultDto.class);

        final Root<T> root = cr.from(entity);
        Expression<?> groupBySelection = groupByExpression.apply(root, cb);
        cr.multiselect(groupBySelection, aggregation.apply(root, cb));
        cr.groupBy(groupBySelection);

        final List<Predicate> predicates = getPredicates(filter, additionalWhereClause, root, cb, cr);
        cr = predicates.isEmpty() ? cr : cr.where(predicates.toArray(new Predicate[]{}));

        return entityManager
                .createQuery(cr)
                .getResultList()
                .stream()
                .collect(Collectors
                        .toMap(i -> i.aggregatedValue() == null ? "Unassigned" : i.aggregatedValue(),
                                i -> i.aggregation().longValue()));
    }

    @Override
    public Long countUsingSecurityFilter(SecurityFilter filter) {
        return countUsingSecurityFilter(filter, null);
    }

    @Override
    public Long countUsingSecurityFilter(SecurityFilter filter,
            TriFunction<Root<T>, CriteriaBuilder, CriteriaQuery<?>, Predicate> additionalWhereClause) {
        CriteriaQuery<Long> cr = createCountCriteriaBuilder(filter, additionalWhereClause, true);
        List<Long> crlist = entityManager.createQuery(cr).getResultList();
        return crlist.get(0);
    }

    @Override
    public Long countRowsUsingSecurityFilter(SecurityFilter filter,
            TriFunction<Root<T>, CriteriaBuilder, CriteriaQuery<?>, Predicate> additionalWhereClause) {
        CriteriaQuery<Long> cr = createCountCriteriaBuilder(filter, additionalWhereClause, false);
        return entityManager.createQuery(cr).getResultList().get(0);
    }

    @Override
    public Integer deleteUsingSecurityFilter(SecurityFilter filter,
            TriFunction<Root<T>, CriteriaBuilder, CriteriaDelete<T>, Predicate> additionalWhereClause) {
        final Class<T> entity = this.entityInformation.getJavaType();
        final CriteriaBuilder cb = entityManager.getCriteriaBuilder();
        CriteriaDelete<T> cd = cb.createCriteriaDelete(entity);
        final Root<T> root = cd.from(entity);

        Predicate additionalWhereClausePredicate = additionalWhereClause.apply(root, cb, cd);
        final List<Predicate> predicates = getPredicates(filter, additionalWhereClausePredicate, root, cb);
        if (!predicates.isEmpty()) {
            cd = cd.where(predicates.toArray(new Predicate[]{}));
        }

        return entityManager.createQuery(cd).executeUpdate();
    }

    @Override
    public List<NameAndUuidDto> listResourceObjects(SecurityFilter securityFilter,
            SingularAttribute<T, String> nameAttribute) {
        return listResourceObjects(securityFilter, nameAttribute, null);
    }

    @Override
    public List<NameAndUuidDto> listResourceObjects(SecurityFilter securityFilter,
            SingularAttribute<T, String> nameAttribute,
            TriFunction<Root<T>, CriteriaBuilder, CriteriaQuery<?>, Predicate> additionalWhereClause) {
        CriteriaQuery<NameAndUuidDto> query = createResourceObjectsQuery(securityFilter, nameAttribute,
                additionalWhereClause);

        return entityManager.createQuery(query).getResultList();
    }

    private CriteriaQuery<NameAndUuidDto> createResourceObjectsQuery(SecurityFilter securityFilter,
            SingularAttribute<T, String> nameAttribute,
            TriFunction<Root<T>, CriteriaBuilder, CriteriaQuery<?>, Predicate> additionalWhereClause) {
        BiFunction<Root<T>, CriteriaBuilder, Expression<String>> factory = nameAttribute == null
                ? null
                : (root, cb) -> root.get(nameAttribute);
        return createResourceObjectsQuery(securityFilter, factory, additionalWhereClause);
    }

    private CriteriaQuery<NameAndUuidDto> createResourceObjectsQuery(SecurityFilter securityFilter,
            BiFunction<Root<T>, CriteriaBuilder, Expression<String>> nameExpressionFactory,
            TriFunction<Root<T>, CriteriaBuilder, CriteriaQuery<?>, Predicate> additionalWhereClause) {
        final Class<T> entity = this.entityInformation.getJavaType();
        final CriteriaBuilder cb = entityManager.getCriteriaBuilder();
        CriteriaQuery<NameAndUuidDto> query = cb.createQuery(NameAndUuidDto.class);
        final Root<T> root = query.from(entity);

        Expression<String> nameExpression = nameExpressionFactory == null
                ? cb.nullLiteral(String.class)
                : nameExpressionFactory.apply(root, cb);

        query.select(cb.construct(NameAndUuidDto.class, root.get("uuid"), nameExpression));

        if (nameExpressionFactory != null) {
            query.orderBy(cb.asc(nameExpression));
        } else {
            query.orderBy(cb.asc(root.get("uuid")));
        }

        final List<Predicate> predicates = getPredicates(securityFilter, additionalWhereClause, root, cb, query);
        if (!predicates.isEmpty()) {
            query = query.where(predicates.toArray(new Predicate[]{}));
        }
        return query;
    }

    @Override
    public List<NameAndUuidDto> listResourceObjects(SecurityFilter securityFilter,
            SingularAttribute<T, String> nameAttribute,
            TriFunction<Root<T>, CriteriaBuilder, CriteriaQuery<?>, Predicate> additionalWhereClause,
            PaginationRequestDto page) {
        CriteriaQuery<NameAndUuidDto> criteriaQuery = createResourceObjectsQuery(securityFilter, nameAttribute,
                additionalWhereClause);

        TypedQuery<NameAndUuidDto> query = entityManager.createQuery(criteriaQuery);
        if (page != null) {
            query.setFirstResult((page.getPageNumber() - 1) * page.getItemsPerPage());
            query.setMaxResults(page.getItemsPerPage());
        }
        return query.getResultList();
    }

    @Override
    public List<NameAndUuidDto> listResourceObjects(SecurityFilter securityFilter,
            BiFunction<Root<T>, CriteriaBuilder, Expression<String>> nameExpressionFactory,
            TriFunction<Root<T>, CriteriaBuilder, CriteriaQuery<?>, Predicate> additionalWhereClause,
            PaginationRequestDto page) {
        CriteriaQuery<NameAndUuidDto> criteriaQuery = createResourceObjectsQuery(securityFilter, nameExpressionFactory,
                additionalWhereClause);

        TypedQuery<NameAndUuidDto> query = entityManager.createQuery(criteriaQuery);
        if (page != null) {
            query.setFirstResult((page.getPageNumber() - 1) * page.getItemsPerPage());
            query.setMaxResults(page.getItemsPerPage());
        }
        return query.getResultList();
    }

    @Override
    public NameAndUuidDto findResourceObject(UUID uuid,
            BiFunction<Root<T>, CriteriaBuilder, Expression<String>> nameExpressionFactory) throws NotFoundException {
        final Class<T> entity = this.entityInformation.getJavaType();
        final CriteriaBuilder cb = entityManager.getCriteriaBuilder();
        CriteriaQuery<NameAndUuidDto> query = cb.createQuery(NameAndUuidDto.class);
        final Root<T> root = query.from(entity);

        Expression<String> nameExpression = nameExpressionFactory == null
                ? cb.nullLiteral(String.class)
                : nameExpressionFactory.apply(root, cb);

        query
                .select(cb.construct(NameAndUuidDto.class, root.get("uuid"), nameExpression))
                .where(cb.equal(root.get("uuid"), uuid));

        return entityManager
                .createQuery(query)
                .getResultList()
                .stream()
                .findFirst()
                .orElseThrow(() -> new NotFoundException(this.entityInformation.getJavaType(), uuid));
    }

    @Override
    public NameAndUuidDto findResourceObject(UUID uuid, SingularAttribute<T, String> nameAttribute)
            throws NotFoundException {
        final Class<T> entity = this.entityInformation.getJavaType();
        final CriteriaBuilder cb = entityManager.getCriteriaBuilder();
        CriteriaQuery<NameAndUuidDto> query = cb.createQuery(NameAndUuidDto.class);
        final Root<T> root = query.from(entity);

        Expression<String> nameExpression = nameAttribute == null
                ? cb.nullLiteral(String.class)
                : root.get(nameAttribute);

        query
                .select(cb.construct(NameAndUuidDto.class, root.get("uuid"), nameExpression))
                .where(cb.equal(root.get("uuid"), uuid));

        return entityManager
                .createQuery(query)
                .getResultList()
                .stream()
                .findFirst()
                .orElseThrow(() -> new NotFoundException(this.entityInformation.getJavaType(), uuid));
    }

    private CriteriaQuery<T> createCriteriaBuilder(final SecurityFilter filter, List<String> fetchAssociations,
            final TriFunction<Root<T>, CriteriaBuilder, CriteriaQuery<?>, Predicate> additionalWhereClause,
            final BiFunction<Root<T>, CriteriaBuilder, Order> order) {
        return createCriteriaBuilder(filter, fetchAssociations, additionalWhereClause, order, null, false);
    }

    private CriteriaQuery<T> createCriteriaBuilder(final SecurityFilter filter, List<String> fetchAssociations,
            final TriFunction<Root<T>, CriteriaBuilder, CriteriaQuery<?>, Predicate> additionalWhereClause,
            final BiFunction<Root<T>, CriteriaBuilder, Order> order, final SortSpecification sort,
            final boolean paged) {
        final Class<T> entity = this.entityInformation.getJavaType();
        final CriteriaBuilder cb = entityManager.getCriteriaBuilder();
        final CriteriaQuery<T> cr = cb.createQuery(entity);
        final Root<T> root = cr.from(entity);

        cr.select(root).distinct(true);

        fetchAssociations(root, fetchAssociations);

        final List<Order> orders = resolveOrdering(root, cb, cr, order, sort, paged);
        if (!orders.isEmpty()) {
            cr.orderBy(orders);
        }

        final List<Predicate> predicates = getPredicates(filter, additionalWhereClause, root, cb, cr);
        return predicates.isEmpty() ? cr : cr.where(predicates.toArray(new Predicate[]{}));
    }

    private CriteriaQuery<UUID> createCriteriaBuilderUuid(final SecurityFilter filter,
            final TriFunction<Root<T>, CriteriaBuilder, CriteriaQuery<?>, Predicate> additionalWhereClause,
            final BiFunction<Root<T>, CriteriaBuilder, Order> order, final SortSpecification sort,
            final boolean paged) {
        final Class<T> entity = this.entityInformation.getJavaType();
        final CriteriaBuilder cb = entityManager.getCriteriaBuilder();
        final CriteriaQuery<UUID> cr = cb.createQuery(UUID.class);
        final Root<T> root = cr.from(entity);

        cr.select(root.get("uuid"));

        final List<Order> orders = resolveOrdering(root, cb, cr, order, sort, paged);
        if (!orders.isEmpty()) {
            cr.orderBy(orders);
        }

        final List<Predicate> predicates = getPredicates(filter, additionalWhereClause, root, cb, cr);
        return predicates.isEmpty() ? cr : cr.where(predicates.toArray(new Predicate[]{}));
    }

    private CriteriaQuery<Long> createCountCriteriaBuilder(final SecurityFilter filter,
            final TriFunction<Root<T>, CriteriaBuilder, CriteriaQuery<?>, Predicate> additionalWhereClause,
            final boolean distinct) {
        final CriteriaBuilder cb = entityManager.getCriteriaBuilder();
        final Class<T> entity = this.entityInformation.getJavaType();
        final CriteriaQuery<Long> cr = cb.createQuery(Long.class);
        final Root<T> root = cr.from(entity);
        cr.select(distinct ? cb.countDistinct(root) : cb.count(root));
        final List<Predicate> predicates = getPredicates(filter, additionalWhereClause, root, cb, cr);
        return predicates.isEmpty() ? cr : cr.where(predicates.toArray(new Predicate[]{}));
    }

    private void fetchAssociations(Root<T> root, List<String> fetchAssociations) {
        Map<String, FetchParent> fetchedAssociationsMap = new HashMap<>();
        for (String fetchAssociation : fetchAssociations) {
            FetchParent fetch = root;
            String associationFullName = null;
            final StringTokenizer stz = new StringTokenizer(fetchAssociation, ".");
            while (stz.hasMoreTokens()) {
                String associationName = stz.nextToken();
                associationFullName = associationFullName == null
                        ? associationName
                        : associationFullName + "." + associationName;
                if (fetchedAssociationsMap.get(associationFullName) == null) {
                    fetch = fetch.fetch(associationName, JoinType.LEFT);
                    fetchedAssociationsMap.put(associationFullName, fetch);
                } else {
                    fetch = fetchedAssociationsMap.get(associationFullName);
                }
            }
        }
    }

    private List<Predicate> getPredicates(SecurityFilter filter, Predicate additionalWhereClause, Root<T> root,
            CriteriaBuilder cb) {
        List<Predicate> predicates = new ArrayList<>();
        if (additionalWhereClause != null) {
            predicates.add(additionalWhereClause);
        }

        if (filter.getParentResourceFilter() != null && filter.getParentRefProperty() == null) {
            throw new ValidationException(ValidationError
                    .create("Unknown parent ref property to filter by parent resource "
                            + filter.getParentResourceFilter().getResource()));
        }

        Predicate resourceFilterPredicate = getPredicateBySecurityResourceFilter(root, filter.getResourceFilter(),
                "uuid");
        Predicate parentResourceFilterPredicate = getPredicateBySecurityResourceFilter(root,
                filter.getParentResourceFilter(), filter.getParentRefProperty());

        // no predicates from security filter means user can retrieve all objects and it is not necessary to evaluate
        // groups and owner associations
        if (resourceFilterPredicate == null && parentResourceFilterPredicate == null) {
            return predicates;
        }

        // init object permissions predicates from resource security filters
        List<Predicate> objectAccessPredicates = initObjectAccessPredicates(resourceFilterPredicate,
                parentResourceFilterPredicate, cb);

        // add owner and group based object access permissions
        getObjectGroupOwnerAccessPredicates(objectAccessPredicates, filter, root, cb);

        // remove null predicates
        objectAccessPredicates = objectAccessPredicates.stream().filter(Objects::nonNull).toList();

        if (!objectAccessPredicates.isEmpty()) {
            predicates
                    .add(objectAccessPredicates.size() == 1
                            ? objectAccessPredicates.getFirst()
                            : cb.or(objectAccessPredicates.toArray(new Predicate[0])));
        }
        return predicates;
    }

    private List<Predicate> getPredicates(SecurityFilter filter,
            TriFunction<Root<T>, CriteriaBuilder, CriteriaQuery<?>, Predicate> additionalWhereClause, Root<T> root,
            CriteriaBuilder cb, CriteriaQuery<?> cr) {
        Predicate additionalWhereClausePredicate = null;
        if (additionalWhereClause != null) {
            additionalWhereClausePredicate = additionalWhereClause.apply(root, cb, cr);
        }

        return getPredicates(filter, additionalWhereClausePredicate, root, cb);
    }

    private List<Predicate> initObjectAccessPredicates(Predicate resourceFilterPredicate,
            Predicate parentResourceFilterPredicate, CriteriaBuilder cb) {
        List<Predicate> objectAccessPredicates = new ArrayList<>();
        if (resourceFilterPredicate != null && parentResourceFilterPredicate != null) {
            objectAccessPredicates.add(cb.and(resourceFilterPredicate, parentResourceFilterPredicate));
        } else if (resourceFilterPredicate != null) {
            objectAccessPredicates.add(resourceFilterPredicate);
        } else {
            objectAccessPredicates.add(parentResourceFilterPredicate);
        }

        return objectAccessPredicates;
    }

    private void getObjectGroupOwnerAccessPredicates(List<Predicate> objectAccessPredicates, SecurityFilter filter,
            Root<T> root, CriteriaBuilder cb) {
        if (filter.getResourceFilter() != null) {
            // check for group membership predicate
            if (filter.getResourceFilter().getResource().hasGroups()
                    && (filter.getResourceFilter().getResourceAction() == ResourceAction.LIST
                            || filter.getResourceFilter().getResourceAction() == ResourceAction.DETAIL)) {
                objectAccessPredicates
                        .add(getPredicateBySecurityResourceFilter(root, filter.getGroupMembersFilter(), "groups.uuid"));
            }
            // check for owner association predicate
            if (filter.getResourceFilter().getResource().hasOwner()) {
                try {
                    NameAndUuidDto userInformation = AuthHelper.getUserIdentification();
                    String ownerAttributePath = root.getJavaType().equals(CryptographicKeyItem.class)
                            ? "%s.owner".formatted(CryptographicKeyItem_.key.getName())
                            : "owner";
                    Join fromOwner = FilterPredicatesBuilder.prepareJoin(root, ownerAttributePath);
                    objectAccessPredicates
                            .add(cb
                                    .equal(FilterPredicatesBuilder.prepareExpression(fromOwner, "ownerUsername"),
                                            userInformation.getName()));
                } catch (ValidationException e) {
                    // cannot apply filter predicate for anonymous user but anonymous user should not have access here
                    // anyway and anyway will be filtered out by SecurityFilter with no permissions
                }
            }
        }
    }

    private Predicate getPredicateBySecurityResourceFilter(Root<T> root, SecurityResourceFilter resourceFilter,
            String attributeName) {
        Predicate predicate = null;
        if (root.getJavaType().equals(CryptographicKeyItem.class)) {
            attributeName = "%s.%s".formatted(CryptographicKeyItem_.key.getName(), attributeName);
        }

        if (resourceFilter != null) {
            From from = root;
            if (attributeName.contains(".")) {
                from = FilterPredicatesBuilder
                        .prepareJoin(root, attributeName.substring(0, attributeName.lastIndexOf(".")));
                attributeName = attributeName.substring(attributeName.lastIndexOf(".") + 1);
            }
            if (resourceFilter.areOnlySpecificObjectsAllowed()) {
                predicate = FilterPredicatesBuilder
                        .prepareExpression(from, attributeName)
                        .in(resourceFilter.getAllowedObjects());
            } else {
                if (!resourceFilter.getForbiddenObjects().isEmpty()) {
                    predicate = FilterPredicatesBuilder
                            .prepareExpression(from, attributeName)
                            .in(resourceFilter.getForbiddenObjects())
                            .not();
                }
            }
        }
        return predicate;
    }

}
