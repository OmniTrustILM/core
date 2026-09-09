package com.otilm.core.util;

import com.otilm.api.exception.ValidationError;
import com.otilm.api.exception.ValidationException;
import com.otilm.api.model.core.auth.Resource;
import com.otilm.api.model.core.search.FilterFieldSource;
import com.otilm.api.model.core.search.SortDirection;
import com.otilm.core.dao.entity.CryptographicKeyItem;
import com.otilm.core.dao.entity.UniquelyIdentified_;
import com.otilm.core.dao.repository.SortSpecification;
import com.otilm.core.enums.FilterField;
import com.otilm.core.enums.ResourceToClass;
import jakarta.persistence.criteria.CommonAbstractCriteria;
import jakarta.persistence.criteria.CriteriaBuilder;
import jakarta.persistence.criteria.Expression;
import jakarta.persistence.criteria.From;
import jakarta.persistence.criteria.Order;
import jakarta.persistence.criteria.Root;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;
import java.util.function.Function;
import org.hibernate.query.NullPrecedence;
import org.hibernate.query.criteria.JpaOrder;

/**
 * Turns a {@link SortSpecification} into the {@link Order} terms of a secured search.
 */
public final class SortOrderBuilder {

    private SortOrderBuilder() {
    }

    /**
     * The ordering of a query that groups by the root's uuid: the aggregate that carries the requested sort value of
     * one root, and the terms to pass to {@code orderBy}. A sort reached through a join has as many values per root as
     * the join has matches, so the query cannot order by the value itself - it orders by the least of them when
     * ascending and the greatest when descending, which is the value that decides where the root belongs.
     */
    public record GroupedOrdering(Expression<?> sortKey, List<Order> orders) {
    }

    /**
     * Whether the sort has to be applied by the query that selects a page of uuids and carries the sort key in its
     * select list, rather than by the entity query directly. Answerable from the specification alone, so a caller can
     * pick the shape of the query before it has a root to resolve against.
     *
     * <p>
     * Two sorts need it, for different reasons. A sort through a join gives a root as many rows as the join has
     * matches, so a window over those rows would underfill the page. An attribute sort resolves to a scalar subquery,
     * and the entity query selects DISTINCT, which the database will not order by an expression absent from the select
     * list.
     */
    public static boolean needsRankedUuidQuery(SortSpecification sort) {
        if (sort == null) {
            return false;
        }
        if (sort.fieldSource() != FilterFieldSource.PROPERTY) {
            return true;
        }
        return !resolveField(sort).getJoinAttributes().isEmpty();
    }

    /**
     * Resolves the ordering of a query that returns one row per root. The requested sort wins over the caller's
     * default; a uuid tie-break is appended whenever anything is ordered or paged, because a single ORDER BY term over
     * a non-unique column leaves the row order inside a group of equal values up to the database, and paging then walks
     * an unstable set.
     *
     * @param defaultOrder the ordering the caller applies when the request names none, or {@code null} for no default
     * @param paged whether the query will be windowed, which is what makes an unstable order observable
     */
    public static List<Order> resolve(Root<?> root, CriteriaBuilder criteriaBuilder, CommonAbstractCriteria query,
            SortSpecification sort, Order defaultOrder, boolean paged) {
        List<Order> orders = new ArrayList<>();
        if (sort != null) {
            // Property-only by construction: needsRankedUuidQuery sends every attribute sort to resolveGrouped, and
            // resolveField refuses a non-property source rather than letting one build an unorderable query here.
            FilterField field = resolveField(root, sort);
            orders.add(primary(criteriaBuilder, resolveExpression(root, field), sort.direction()));
        } else if (defaultOrder != null) {
            orders.add(defaultOrder);
        }

        if (!orders.isEmpty() || paged) {
            tieBreak(root, criteriaBuilder).ifPresent(orders::add);
        }

        return List.copyOf(orders);
    }

    /**
     * Resolves the ordering of a query grouped by the root's uuid. Only a sort that traverses a join needs it, and such
     * a sort is only offered on a resource keyed by a uuid, so a root without one is a caller error rather than a
     * request the ordering has to degrade for.
     */
    public static GroupedOrdering resolveGrouped(Root<?> root, CriteriaBuilder criteriaBuilder,
            CommonAbstractCriteria query, SortSpecification sort) {
        String fieldName;
        Expression<?> sortKey;
        if (sort.fieldSource() == FilterFieldSource.PROPERTY) {
            FilterField field = resolveField(root, sort);
            fieldName = field.name();
            sortKey = aggregate(criteriaBuilder, resolveExpression(root, field), sort.direction());
        } else {
            fieldName = sort.fieldIdentifier();
            sortKey = aggregate(criteriaBuilder,
                    FilterPredicatesBuilder.getAttributeSortKey(criteriaBuilder, query, root, sort), sort.direction());
        }

        Order tieBreak = tieBreak(root, criteriaBuilder)
                .orElseThrow(() -> new ValidationException(
                        ValidationError.create("Field %s cannot be sorted on this resource.".formatted(fieldName))));

        return new GroupedOrdering(sortKey, List.of(primary(criteriaBuilder, sortKey, sort.direction()), tieBreak));
    }

    /**
     * Puts the rows of the second phase of a two-phase listing back into the order of the first.
     *
     * <p>
     * The listing selects a page of uuids in the requested order and then loads the objects with a {@code uuid IN
     * (...)} query, whose own order is whatever that query defines. Ordering only the first phase is therefore
     * discarded by the second, and the ordering survives solely as the rank of the uuid list. Applied whether or not
     * the request named a sort: the ranked list is the one carrying the tie-break, so re-ranking is also what makes a
     * default-ordered page stable across page boundaries when the default term has ties.
     *
     * @param rankedUuids the uuids in the order the first phase returned them
     * @param rows the objects the second phase loaded, in any order
     * @param uuidOf reads the uuid of a loaded object
     */
    public static <T> List<T> rankBy(List<UUID> rankedUuids, List<T> rows, Function<T, UUID> uuidOf) {
        Map<UUID, Integer> rank = new HashMap<>();
        for (int i = 0; i < rankedUuids.size(); i++) {
            rank.put(rankedUuids.get(i), i);
        }
        // A row whose uuid is not in the ranked list cannot happen for a query keyed by that list, but sorting it last
        // keeps the method total rather than throwing on a caller that passes a wider row set.
        return rows
                .stream()
                .sorted(Comparator.comparingInt(row -> rank.getOrDefault(uuidOf.apply(row), Integer.MAX_VALUE)))
                .toList();
    }

    /**
     * The requested ordering of one sort expression, with the rows that have no value for it pinned last.
     *
     * <p>
     * A column the row has nothing to show for must never lead the page, and reversing the sort must not put those rows
     * first either - which is what PostgreSQL's own default would do, since it orders nulls last ascending and first
     * descending. Shared by both sort paths so a nullable column cannot place its blanks differently depending on
     * whether the ordering happened to be reached through a join or a subquery.
     */
    private static Order primary(CriteriaBuilder criteriaBuilder, Expression<?> expression, SortDirection direction) {
        Order order = direction == SortDirection.DESC
                ? criteriaBuilder.desc(expression)
                : criteriaBuilder.asc(expression);
        return ((JpaOrder) order).nullPrecedence(NullPrecedence.LAST);
    }

    /**
     * The value of the sort expression that decides where a root belongs among the rows the join multiplied it into:
     * the least of them when ascending, the greatest when descending.
     */
    @SuppressWarnings({"unchecked", "rawtypes"})
    private static Expression<?> aggregate(CriteriaBuilder criteriaBuilder, Expression<?> expression,
            SortDirection direction) {
        return direction == SortDirection.DESC
                ? criteriaBuilder.greatest((Expression) expression)
                : criteriaBuilder.least((Expression) expression);
    }

    /**
     * Resolves the field attribute through the metamodel, because Hibernate 7 drops the implicit downcast a name lookup
     * needs for an attribute declared on a subtype of the root.
     */
    private static Expression<?> resolveExpression(Root<?> root, FilterField field) {
        String joinPath = FilterPredicatesBuilder.buildPathToProperty(field.getJoinAttributes(), null);
        try {
            From<?, ?> from = joinPath.isEmpty() ? root : FilterPredicatesBuilder.prepareJoin(root, joinPath);
            return FilterPredicatesBuilder.resolveFieldPath(from, field.getFieldAttribute());
        } catch (IllegalArgumentException e) {
            throw new ValidationException(
                    ValidationError.create("Field %s cannot be sorted on this resource.".formatted(field.name())));
        }
    }

    private static FilterField resolveField(SortSpecification sort) {
        if (sort.fieldSource() != FilterFieldSource.PROPERTY) {
            throw new ValidationException(ValidationError
                    .create("Sorting by %s fields is not supported.".formatted(sort.fieldSource().getLabel())));
        }
        FilterField field;
        try {
            field = FilterField.valueOf(sort.fieldIdentifier());
        } catch (IllegalArgumentException e) {
            throw new ValidationException(
                    ValidationError.create("Unknown sort field identifier %s.".formatted(sort.fieldIdentifier())));
        }
        // Refused against the predicate the catalogue publishes as `sortable`, widened to the listings that publish
        // no columns at all and order from their own code instead. So a request the frontend was told to withhold is
        // answered with an error rather than with a silently unordered page. Checked before the path is resolved,
        // because several of these fields do resolve to a path - it is just not the value the column shows.
        if (!SearchHelper.isOrderableOnListing(field)) {
            throw new ValidationException(
                    ValidationError.create("Field %s cannot be used to order this listing.".formatted(field.name())));
        }
        return field;
    }

    /**
     * The field the identifier names, rejected unless the queried resource is the one that declares it. The identifier
     * is unique across every resource, but the attribute path behind it need not be: a field declared on a mapped
     * superclass - {@code Audited.created}, say - resolves against any entity that inherits it, so path resolution
     * alone would let a field of another resource through.
     */
    private static FilterField resolveField(Root<?> root, SortSpecification sort) {
        FilterField field = resolveField(sort);
        // The resource the listing selects when the caller named one, which is authoritative: an entity outside
        // ResourceToClass maps to no resource, and deriving it from the root alone silently skips this check there.
        Resource resource = sort.resource() == null ? resourceOf(root) : sort.resource();
        if (resource != null && field.getRootResource() != resource) {
            throw new ValidationException(ValidationError
                    .create("Field %s does not belong to resource %s.".formatted(field.name(), resource.getLabel())));
        }
        return field;
    }

    /**
     * The resource the queried entity belongs to, or {@code null} for an entity that is not a resource of its own and
     * so has no field catalogue to check an identifier against. Key items carry the fields of the key they belong to,
     * the same exception the attribute filter path makes.
     */
    private static Resource resourceOf(Root<?> root) {
        return root.getJavaType().equals(CryptographicKeyItem.class)
                ? Resource.CRYPTOGRAPHIC_KEY
                : ResourceToClass.getResourceByClass(root.getJavaType());
    }

    /**
     * The uuid of the queried entity, when it has one. Entities keyed by a generated id instead - the audit log - have
     * no uuid to break ties with, and keep whatever order their own default term produces.
     */
    private static Optional<Order> tieBreak(Root<?> root, CriteriaBuilder criteriaBuilder) {
        try {
            root.getModel().getSingularAttribute(UniquelyIdentified_.UUID);
        } catch (IllegalArgumentException e) {
            return Optional.empty();
        }
        return Optional.of(criteriaBuilder.asc(root.get(UniquelyIdentified_.UUID)));
    }
}
