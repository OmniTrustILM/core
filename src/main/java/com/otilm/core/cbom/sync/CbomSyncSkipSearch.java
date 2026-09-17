package com.otilm.core.cbom.sync;

import com.otilm.api.exception.ValidationError;
import com.otilm.api.exception.ValidationException;
import com.otilm.api.model.client.certificate.SearchFilterRequestDto;
import com.otilm.api.model.client.certificate.SearchSortRequestDto;
import com.otilm.api.model.common.enums.PlatformEnum;
import com.otilm.api.model.core.cbom.CbomSyncSkipState;
import com.otilm.api.model.core.search.FilterConditionOperator;
import com.otilm.api.model.core.search.FilterFieldSource;
import com.otilm.api.model.core.search.FilterFieldType;
import com.otilm.api.model.core.search.SearchFieldDataByGroupDto;
import com.otilm.api.model.core.search.SearchFieldDataDto;
import com.otilm.api.model.core.search.SortDirection;
import com.otilm.core.dao.entity.cbom.CbomSyncSkip;
import com.otilm.core.util.FilterPredicatesBuilder;
import jakarta.persistence.criteria.CriteriaBuilder;
import jakarta.persistence.criteria.Path;
import jakarta.persistence.criteria.Predicate;
import jakarta.persistence.criteria.Root;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import org.springframework.data.domain.Sort;
import org.springframework.data.jpa.domain.Specification;

/**
 * The operator list of the documents the sync could not store: which fields it filters and sorts on, and how.
 *
 * <p>
 * The list speaks the platform's canonical search request, but not through {@code FilterField}: those fields are rooted
 * at a listed {@code Resource}, and the skip rows are not one -- they are bookkeeping under the CBOM inventory's own
 * permissions -- so a field rooted at {@code Resource.CBOM} would be offered to the CBOM listing's sort and column
 * pipeline, where it has no meaning. Two filter fields and four sort keys, served by hand, is the whole surface; an
 * identifier or a condition outside it is refused as the request's own error (422), the way the platform listings
 * refuse an unknown sort.
 */
public final class CbomSyncSkipSearch {

    public static final String STATE = "CBOM_SYNC_SKIP_STATE";
    public static final String SERIAL_NUMBER = "CBOM_SYNC_SKIP_SERIAL_NUMBER";
    public static final String LAST_ATTEMPT_AT = "CBOM_SYNC_SKIP_LAST_ATTEMPT_AT";
    public static final String FIRST_SKIPPED_AT = "CBOM_SYNC_SKIP_FIRST_SKIPPED_AT";
    public static final String ATTEMPTS = "CBOM_SYNC_SKIP_ATTEMPTS";

    /** Newest failure first; the UUID breaks ties so paging never repeats or drops a row. */
    public static final Sort DEFAULT_ORDER = Sort.by(Sort.Order.desc("lastAttemptAt"), Sort.Order.asc("uuid"));

    private static final Map<String, String> SORT_ATTRIBUTES = Map
            .of(LAST_ATTEMPT_AT, "lastAttemptAt", FIRST_SKIPPED_AT, "firstSkippedAt", ATTEMPTS, "attempts",
                    SERIAL_NUMBER, "serialNumber");

    private static final List<FilterConditionOperator> STATE_CONDITIONS = List
            .of(FilterConditionOperator.EQUALS, FilterConditionOperator.NOT_EQUALS);
    private static final List<FilterConditionOperator> SERIAL_NUMBER_CONDITIONS = List
            .of(FilterConditionOperator.EQUALS, FilterConditionOperator.NOT_EQUALS, FilterConditionOperator.CONTAINS,
                    FilterConditionOperator.NOT_CONTAINS, FilterConditionOperator.STARTS_WITH);

    private CbomSyncSkipSearch() {
    }

    /**
     * What the searchable-fields operation publishes: the two filter fields, the serial number also orderable. The
     * three sort-only keys (last attempt, first failure, attempts) are named on the list operation and stay out of the
     * catalogue: an entry with no condition would be offered as a filter. {@code displayable} is left unset, as the
     * contract says: the rows have a fixed shape.
     */
    public static List<SearchFieldDataByGroupDto> searchableFields() {
        SearchFieldDataDto state = new SearchFieldDataDto();
        state.setFieldIdentifier(STATE);
        state.setFieldLabel("State");
        state.setType(FilterFieldType.LIST);
        state.setConditions(STATE_CONDITIONS);
        state.setMultiValue(true);
        state.setPlatformEnum(PlatformEnum.CBOM_SYNC_SKIP_STATE);
        state.setValue(Arrays.stream(CbomSyncSkipState.values()).map(CbomSyncSkipState::getCode).toList());
        state.setSortable(false);

        SearchFieldDataDto serialNumber = new SearchFieldDataDto();
        serialNumber.setFieldIdentifier(SERIAL_NUMBER);
        serialNumber.setFieldLabel("Serial Number");
        serialNumber.setType(FilterFieldType.STRING);
        serialNumber.setConditions(SERIAL_NUMBER_CONDITIONS);
        serialNumber.setMultiValue(false);
        serialNumber.setSortable(true);

        return List.of(new SearchFieldDataByGroupDto(List.of(serialNumber, state), FilterFieldSource.PROPERTY));
    }

    /** The request's filters as one predicate; an empty list matches everything. */
    public static Specification<CbomSyncSkip> specification(List<SearchFilterRequestDto> filters) {
        return (root, query, cb) -> {
            List<Predicate> predicates = new ArrayList<>();
            for (SearchFilterRequestDto filter : filters == null ? List.<SearchFilterRequestDto>of() : filters) {
                predicates.add(predicate(filter, root, cb));
            }
            return cb.and(predicates.toArray(Predicate[]::new));
        };
    }

    /** The request's sort, or {@link #DEFAULT_ORDER} when it carries none. */
    public static Sort sort(SearchSortRequestDto sort) {
        if (sort == null) {
            return DEFAULT_ORDER;
        }
        String attribute = SORT_ATTRIBUTES.get(sort.getFieldIdentifier());
        if (sort.getFieldSource() != FilterFieldSource.PROPERTY || attribute == null) {
            throw new ValidationException(ValidationError
                    .create("The sync skip list cannot be ordered by %s; use one of %s"
                            .formatted(sort.getFieldIdentifier(),
                                    SORT_ATTRIBUTES.keySet().stream().sorted().toList())));
        }
        Sort.Direction direction = sort.getDirection() == SortDirection.DESC ? Sort.Direction.DESC : Sort.Direction.ASC;
        return Sort.by(new Sort.Order(direction, attribute), Sort.Order.asc("uuid"));
    }

    private static Predicate predicate(SearchFilterRequestDto filter, Root<CbomSyncSkip> root, CriteriaBuilder cb) {
        if (filter.getFieldSource() != FilterFieldSource.PROPERTY) {
            throw unknownField(filter.getFieldIdentifier());
        }
        return switch (filter.getFieldIdentifier() == null ? "" : filter.getFieldIdentifier()) {
            case STATE -> statePredicate(filter, root.get("state"), cb);
            case SERIAL_NUMBER -> serialNumberPredicate(filter, root.get("serialNumber"), cb);
            default -> throw unknownField(filter.getFieldIdentifier());
        };
    }

    private static Predicate statePredicate(SearchFilterRequestDto filter, Path<CbomSyncSkipState> state,
            CriteriaBuilder cb) {
        List<CbomSyncSkipState> states = values(filter)
                .stream()
                .map(code -> CbomSyncSkipState.findByCode(String.valueOf(code)))
                .toList();
        return switch (filter.getCondition()) {
            case EQUALS -> state.in(states);
            case NOT_EQUALS -> cb.not(state.in(states));
            case null, default -> throw unknownCondition(filter, STATE_CONDITIONS);
        };
    }

    /**
     * Case-sensitive, as the platform's own string predicates are ({@link FilterPredicatesBuilder}), so a serial number
     * filter answers the same here and on the CBOM inventory. The value's {@code %} and {@code _} match literally.
     */
    private static Predicate serialNumberPredicate(SearchFilterRequestDto filter, Path<String> serialNumber,
            CriteriaBuilder cb) {
        List<Object> values = values(filter);
        if (values.size() > 1) {
            throw new ValidationException(
                    ValidationError.create("A filter on %s takes one value".formatted(filter.getFieldIdentifier())));
        }
        String value = String.valueOf(values.getFirst());
        String literal = FilterPredicatesBuilder.escapeLikeWildcards(value);
        char escape = FilterPredicatesBuilder.LIKE_ESCAPE_CHAR;
        return switch (filter.getCondition()) {
            case EQUALS -> cb.equal(serialNumber, value);
            case NOT_EQUALS -> cb.notEqual(serialNumber, value);
            case CONTAINS -> cb.like(serialNumber, "%" + literal + "%", escape);
            case NOT_CONTAINS -> cb.notLike(serialNumber, "%" + literal + "%", escape);
            case STARTS_WITH -> cb.like(serialNumber, literal + "%", escape);
            case null, default -> throw unknownCondition(filter, SERIAL_NUMBER_CONDITIONS);
        };
    }

    /** A filter value arrives as one value or a list of them; both are read as a list, never empty. */
    private static List<Object> values(SearchFilterRequestDto filter) {
        Object value = filter.getValue();
        List<Object> values = value instanceof List<?> list ? new ArrayList<>(list) : new ArrayList<>();
        if (!(value instanceof List<?>) && value != null) {
            values.add(value);
        }
        values.removeIf(v -> v == null || String.valueOf(v).isBlank());
        if (values.isEmpty()) {
            throw new ValidationException(
                    ValidationError.create("A filter on %s needs a value".formatted(filter.getFieldIdentifier())));
        }
        return values;
    }

    private static ValidationException unknownField(String identifier) {
        return new ValidationException(ValidationError
                .create("The sync skip list cannot be filtered by %s; use %s or %s"
                        .formatted(identifier, STATE, SERIAL_NUMBER)));
    }

    private static ValidationException unknownCondition(SearchFilterRequestDto filter,
            List<FilterConditionOperator> allowed) {
        String condition = filter.getCondition() == null ? "none" : filter.getCondition().getCode();
        return new ValidationException(ValidationError
                .create("The condition %s does not apply to %s; use one of %s"
                        .formatted(condition, filter.getFieldIdentifier(),
                                allowed.stream().map(FilterConditionOperator::getCode).toList())));
    }
}
