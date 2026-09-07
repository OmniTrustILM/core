package com.otilm.core.util;

import com.otilm.api.exception.ValidationError;
import com.otilm.api.exception.ValidationException;
import com.otilm.api.model.client.certificate.SearchFilterRequestDto;
import com.otilm.api.model.common.attribute.common.AttributeType;
import com.otilm.api.model.common.attribute.common.content.AttributeContentType;
import com.otilm.api.model.common.enums.BitMaskEnum;
import com.otilm.api.model.common.enums.IPlatformEnum;
import com.otilm.api.model.core.auth.Resource;
import com.otilm.api.model.core.search.FilterConditionOperator;
import com.otilm.api.model.core.search.FilterFieldSource;
import com.otilm.core.attribute.engine.AttributeColumnProjector;
import com.otilm.core.attribute.engine.AttributeEngine.CustomAttributeContentFilter;
import com.otilm.core.dao.entity.AttributeContent2Object;
import com.otilm.core.dao.entity.AttributeContent2Object_;
import com.otilm.core.dao.entity.AttributeContentItem_;
import com.otilm.core.dao.entity.AttributeDefinition_;
import com.otilm.core.dao.entity.Cbom_;
import com.otilm.core.dao.entity.CryptographicKeyItem;
import com.otilm.core.dao.entity.CryptographicKeyItem_;
import com.otilm.core.dao.entity.GroupAssociation;
import com.otilm.core.dao.entity.GroupAssociation_;
import com.otilm.core.dao.entity.ResourceObjectAssociation_;
import com.otilm.core.dao.entity.ScheduledJobHistory;
import com.otilm.core.dao.entity.UniquelyIdentified_;
import com.otilm.core.dao.entity.cbom.CryptoAssetSource;
import com.otilm.core.dao.entity.cbom.CryptoAssetSource_;
import com.otilm.core.dao.entity.cbom.CryptoAsset_;
import com.otilm.core.dao.repository.SortSpecification;
import com.otilm.core.enums.FilterField;
import com.otilm.core.enums.ResourceToClass;
import com.otilm.core.enums.SearchFieldTypeEnum;
import com.otilm.core.model.AttributeFieldIdentifier;
import com.otilm.core.model.cbom.CryptoAssetIdentityGuard;
import jakarta.persistence.EntityManager;
import jakarta.persistence.Query;
import jakarta.persistence.criteria.CommonAbstractCriteria;
import jakarta.persistence.criteria.CriteriaBuilder;
import jakarta.persistence.criteria.Expression;
import jakarta.persistence.criteria.From;
import jakarta.persistence.criteria.Join;
import jakarta.persistence.criteria.JoinType;
import jakarta.persistence.criteria.Path;
import jakarta.persistence.criteria.Predicate;
import jakarta.persistence.criteria.Root;
import jakarta.persistence.criteria.Subquery;
import jakarta.persistence.metamodel.Attribute;
import jakarta.persistence.metamodel.PluralAttribute;
import jakarta.persistence.metamodel.SingularAttribute;
import java.io.Serializable;
import java.time.LocalDate;
import java.time.LocalDateTime;
import java.time.LocalTime;
import java.time.Period;
import java.time.ZonedDateTime;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.StringTokenizer;
import java.util.UUID;
import java.util.function.Supplier;
import java.util.regex.Pattern;
import java.util.regex.PatternSyntaxException;
import java.util.stream.Collectors;
import javax.xml.datatype.DatatypeConfigurationException;
import javax.xml.datatype.DatatypeFactory;
import javax.xml.datatype.Duration;
import org.hibernate.query.criteria.HibernateCriteriaBuilder;
import org.hibernate.query.criteria.JpaExpression;
import org.hibernate.query.criteria.JpaSubQuery;

public class FilterPredicatesBuilder {

    public static final String EMPTY_JSON_ARRAY = "[]";
    public static final String NULL_JSON_ARRAY = "[null]";

    private FilterPredicatesBuilder() {
        throw new IllegalStateException("Static utility class");
    }

    private static final List<AttributeContentType> castedAttributeContentData = List
            .of(AttributeContentType.INTEGER, AttributeContentType.FLOAT, AttributeContentType.DATE,
                    AttributeContentType.TIME, AttributeContentType.DATETIME);
    private static final String JSONB_EXTRACT_PATH_TEXT_FUNCTION_NAME = "jsonb_extract_path_text";
    private static final String TEXTREGEXEQ_FUNCTION_NAME = "textregexeq";
    private static final String ARRAY_CONTAINS_FUNCTION_NAME = PostgresFunctionContributor.ARRAY_CONTAINS;

    private static final char LIKE_ESCAPE_CHAR = '\\';
    private static final String ARRAY_ITEM_CONTAINS_FUNCTION_NAME = PostgresFunctionContributor.ARRAY_ITEM_CONTAINS;

    private static final Set<FilterConditionOperator> OID_CONDITIONS_A_NULL_OID_SATISFIES = Set
            .of(FilterConditionOperator.NOT_EQUALS, FilterConditionOperator.NOT_CONTAINS);
    private static final Set<FilterConditionOperator> OID_CONDITIONS_A_NULL_OID_NEVER_SATISFIES = Set
            .of(FilterConditionOperator.EQUALS, FilterConditionOperator.CONTAINS, FilterConditionOperator.STARTS_WITH,
                    FilterConditionOperator.ENDS_WITH, FilterConditionOperator.MATCHES,
                    FilterConditionOperator.NOT_MATCHES);

    /**
     * The predicate a listing applies for the filters a request carries.
     *
     * @param contentFilterSource the caller's custom-attribute permissions, read only when a filter reaches custom
     * attribute content. Every listing supplies it, since what a request may name is the caller's choice.
     */
    public static <T> Predicate getFiltersPredicate(final CriteriaBuilder criteriaBuilder,
            final CommonAbstractCriteria query, final Root<T> root, final List<SearchFilterRequestDto> filterDtos,
            final Supplier<CustomAttributeContentFilter> contentFilterSource) {
        Map<String, From> joinedAssociations = new HashMap<>();

        // An explicit filter on the refuted-OID facet is the caller opting into matching refuted OID
        // values, so the carve-outs below switch off for the whole request; the facet's own predicate
        // then selects rows by refutedness. Without this, combining the facet with an OID filter would
        // be self-contradictory and always empty.
        boolean refutedOidsOptedIn = filterDtos != null && filterDtos
                .stream()
                .anyMatch(dto -> dto.getFieldSource() == FilterFieldSource.PROPERTY
                        && FilterField.CBOM_ASSET_OID_REFUTED.name().equals(dto.getFieldIdentifier()));

        List<Predicate> predicates = new ArrayList<>();
        if (filterDtos != null) {
            for (SearchFilterRequestDto filterDto : filterDtos) {
                if (filterDto.getFieldSource() == FilterFieldSource.PROPERTY) {
                    predicates
                            .add(getPropertyFilterPredicate(criteriaBuilder, query, root, filterDto, joinedAssociations,
                                    refutedOidsOptedIn));
                } else {
                    predicates
                            .add(getAttributeFilterPredicate(criteriaBuilder, query, root, filterDto,
                                    contentFilterSource));
                }
            }
        }

        return criteriaBuilder.and(predicates.toArray(new Predicate[]{}));
    }

    /**
     * The {@code EXISTS} subquery one attribute-sourced filter selects rows by, gated by the readability checks the
     * projection applies to the same content.
     */
    private static <T> Predicate getAttributeFilterPredicate(final CriteriaBuilder criteriaBuilder,
            final CommonAbstractCriteria query, final Root<T> root, final SearchFilterRequestDto filterDto,
            final Supplier<CustomAttributeContentFilter> contentFilterSource) {
        // A listing that never resolved the caller's attribute permissions must not read content without them.
        if (contentFilterSource == null) {
            throw new ValidationException(ValidationError
                    .create("Filtering by %s was not resolved against the caller's attribute permissions."
                            .formatted(filterDto.getFieldIdentifier())));
        }
        final Subquery<Integer> subquery = query.subquery(Integer.class);
        final Root<AttributeContent2Object> subqueryRoot = subquery.from(AttributeContent2Object.class);
        final Join joinContentItem = subqueryRoot.join(AttributeContent2Object_.attributeContentItem, JoinType.INNER);
        final Join joinDefinition = joinContentItem.join(AttributeContentItem_.attributeDefinition, JoinType.INNER);

        final AttributeType attributeType = filterDto.getFieldSource().getAttributeType();
        final String identifier = filterDto.getFieldIdentifier();
        final AttributeFieldIdentifier fieldIdentifier = AttributeFieldIdentifier.parse(identifier);
        if (fieldIdentifier == null || fieldIdentifier.contentType() == null) {
            throw new ValidationException(ValidationError
                    .create("Filter field identifier %s does not name an attribute.".formatted(identifier)));
        }
        final AttributeContentType contentType = fieldIdentifier.contentType();
        final String attributeName = fieldIdentifier.attributeName();
        final boolean readsStoredValue = filterDto.getCondition() != FilterConditionOperator.EMPTY
                && filterDto.getCondition() != FilterConditionOperator.NOT_EMPTY;
        requireFilterableContentType(identifier, contentType, readsStoredValue);
        final boolean isNotExistCondition = List
                .of(FilterConditionOperator.NOT_EQUALS, FilterConditionOperator.NOT_CONTAINS,
                        FilterConditionOperator.EMPTY, FilterConditionOperator.NOT_MATCHES)
                .contains(filterDto.getCondition());

        final Resource resource = attributeResourceOf(root);
        final String objectUuidPath = attributeObjectUuidPath(root, attributeType);

        List<Predicate> predicates = new ArrayList<>(attributeCorrelationPredicates(criteriaBuilder, root, subqueryRoot,
                joinDefinition, attributeType, contentType, attributeName, resource, objectUuidPath));

        predicates
                .addAll(attributeReadabilityPredicates(criteriaBuilder, joinContentItem, joinDefinition, attributeType,
                        contentFilterSource, readsStoredValue));

        if (readsStoredValue) {
            Expression<String> attributeContentExpression = criteriaBuilder
                    .function(JSONB_EXTRACT_PATH_TEXT_FUNCTION_NAME, String.class,
                            joinContentItem.get(AttributeContentItem_.json),
                            criteriaBuilder.literal(contentType.isFilterByData() ? "data" : "reference"));
            CriteriaBuilder.SimpleCase<AttributeContentType, Object> contentTypeCaseExpression = criteriaBuilder
                    .selectCase(joinDefinition.get(AttributeDefinition_.contentType));

            if (castedAttributeContentData.contains(contentType)) {
                contentTypeCaseExpression
                        .when(contentType,
                                ((JpaExpression) attributeContentExpression).cast(contentType.getContentDataClass()))
                        .otherwise(criteriaBuilder.nullLiteral(contentType.getContentDataClass()));
            } else {
                contentTypeCaseExpression
                        .when(contentType, attributeContentExpression)
                        .otherwise(criteriaBuilder.nullLiteral(String.class));
            }

            Predicate conditionPredicate = getAttributeFilterConditionPredicate(criteriaBuilder, filterDto,
                    contentTypeCaseExpression, contentType);
            predicates.add(conditionPredicate);
        }

        subquery.select(criteriaBuilder.literal(1)).where(predicates.toArray(new Predicate[]{}));
        return isNotExistCondition
                ? criteriaBuilder.not(criteriaBuilder.exists(subquery))
                : criteriaBuilder.exists(subquery);
    }

    private static Predicate getAttributeFilterConditionPredicate(final CriteriaBuilder criteriaBuilder,
            final SearchFilterRequestDto filterDto, final Expression expression,
            final AttributeContentType contentType) {
        List<Object> filterValues = prepareAttributeFilterValues(filterDto, contentType);
        boolean multipleValues = filterValues.size() > 1;

        Object filterValue = filterValues.isEmpty() ? null : filterValues.getFirst();
        FilterConditionOperator conditionOperator = switch (filterDto.getCondition()) {
            case NOT_EQUALS -> FilterConditionOperator.EQUALS;
            case NOT_CONTAINS -> FilterConditionOperator.CONTAINS;
            case NOT_MATCHES -> FilterConditionOperator.MATCHES;
            default -> filterDto.getCondition();
        };
        ZonedDateTime nowDateTime = ZonedDateTime.now();
        return switch (conditionOperator) {
            case EQUALS ->
                multipleValues ? expression.in(filterValues) : criteriaBuilder.equal(expression, filterValue);
            case STARTS_WITH -> criteriaBuilder.like(expression, filterValue + "%");
            case ENDS_WITH -> criteriaBuilder.like(expression, "%" + filterValue);
            case CONTAINS -> criteriaBuilder.like(expression, "%" + filterValue + "%");
            case GREATER -> criteriaBuilder.greaterThan(expression, (Expression) criteriaBuilder.literal(filterValue));
            case GREATER_OR_EQUAL ->
                criteriaBuilder.greaterThanOrEqualTo(expression, (Expression) criteriaBuilder.literal(filterValue));
            case LESSER -> criteriaBuilder.lessThan(expression, (Expression) criteriaBuilder.literal(filterValue));
            case LESSER_OR_EQUAL ->
                criteriaBuilder.lessThanOrEqualTo(expression, (Expression) criteriaBuilder.literal(filterValue));
            case IN_PAST -> {
                Duration duration = (Duration) filterValues.getFirst();
                yield criteriaBuilder
                        .between(expression,
                                nowDateTime
                                        .minus(Period.of(duration.getYears(), duration.getMonths(), duration.getDays()))
                                        .minusHours(duration.getHours())
                                        .minusMinutes(duration.getMinutes())
                                        .minusSeconds(duration.getSeconds()),
                                nowDateTime);
            }
            case IN_NEXT -> {
                Duration duration = (Duration) filterValues.getFirst();
                yield criteriaBuilder
                        .between(expression, nowDateTime,
                                nowDateTime
                                        .plus(Period.of(duration.getYears(), duration.getMonths(), duration.getDays()))
                                        .plusHours(duration.getHours())
                                        .plusMinutes(duration.getMinutes())
                                        .plusSeconds(duration.getSeconds()));
            }
            case MATCHES -> {
                validateRegexForDbQuery(filterValues.getFirst().toString());
                yield criteriaBuilder
                        .equal(criteriaBuilder
                                .function(TEXTREGEXEQ_FUNCTION_NAME, Boolean.class, expression,
                                        criteriaBuilder.literal(filterValues.getFirst())),
                                true);
            }
            case null, default -> null;
        };
    }

    private static List<Object> prepareAttributeFilterValues(final SearchFilterRequestDto filterDto,
            final AttributeContentType contentType) {
        Serializable filterValue = filterDto.getValue();

        if (filterValue == null) {
            return List.of();
        }

        final List<Object> preparedFilterValues = new ArrayList<>();
        List<Object> filterValues = filterValue instanceof List<?> ? (List<Object>) filterValue : List.of(filterValue);
        for (Object value : filterValues) {
            String stringValue = value.toString();
            Object preparedValue;
            if (filterDto.getCondition() == FilterConditionOperator.IN_NEXT
                    || filterDto.getCondition() == FilterConditionOperator.IN_PAST) {
                preparedValue = prepareDurationValue(contentType, stringValue);
            } else {
                preparedValue = switch (contentType) {
                    case BOOLEAN -> Boolean.parseBoolean(stringValue) ? "true" : "false";
                    case INTEGER -> {
                        try {
                            yield Integer.parseInt(stringValue);
                        } catch (NumberFormatException e) {
                            throw new ValidationException(
                                    "Filter field value " + stringValue + " cannot be parsed as an Integer.");
                        }
                    }
                    case FLOAT -> {
                        try {
                            yield Float.parseFloat(stringValue);
                        } catch (NumberFormatException e) {
                            throw new ValidationException(
                                    "Filter field value " + stringValue + " cannot be parsed as a Float.");
                        }
                    }
                    case DATE -> LocalDate.parse(stringValue);
                    case TIME -> LocalTime.parse(stringValue);
                    case DATETIME -> {
                        if (!stringValue.contains("+") && !stringValue.endsWith("Z")) {
                            stringValue += "Z";
                        }
                        yield ZonedDateTime
                                .parse(stringValue, DateTimeFormatter
                                        .ofPattern(
                                                "[yyyy-MM-dd'T'HH:mm:ss.SSSXXX][yyyy-MM-dd'T'HH:mm:ssXXX][yyyy-MM-dd'T'HH:mmXXX]"));
                    }
                    case null, default -> stringValue;
                };
            }

            preparedFilterValues.add(preparedValue);
        }

        return preparedFilterValues;
    }

    private static Object prepareDurationValue(AttributeContentType contentType, String stringValue) {
        Object preparedValue;
        if (contentType == AttributeContentType.DATE) {
            stringValue = extractDateFromDuration(stringValue);
        }
        try {
            preparedValue = DatatypeFactory.newInstance().newDuration(stringValue);
        } catch (DatatypeConfigurationException e) {
            throw new ValidationException("Cannot parse value " + stringValue + " to a Duration: " + e.getMessage());
        }
        return preparedValue;
    }

    /**
     * Resolves {@code fieldAttribute} as a path on {@code from}.
     *
     * <p>
     * An attribute declared on an inheritance subtype of what {@code from} resolves to is addressed through the
     * metamodel attribute itself rather than by name. The resulting path carries no restriction to that subtype, so the
     * query still spans the whole hierarchy. Every other attribute is addressed by name.
     *
     * @param from the root or join the filter field is resolved against
     * @param fieldAttribute the attribute being filtered on
     * @return the path to the attribute
     * @throws ValidationException if {@code fieldAttribute} is declared on a subtype but is not singular
     */
    @SuppressWarnings({"unchecked", "rawtypes"})
    static <Y> Path<Y> resolveFieldPath(final From from, final Attribute<?, ?> fieldAttribute) {
        if (!isDeclaredOnStrictSubtypeOf(from, fieldAttribute)) {
            return from.get(fieldAttribute.getName());
        }
        if (!(fieldAttribute instanceof SingularAttribute<?, ?> singularAttribute)) {
            throw new ValidationException("Filter field " + fieldAttribute.getName() + " is declared on subtype "
                    + fieldAttribute.getDeclaringType().getJavaType().getSimpleName()
                    + " and is not singular, which filter resolution does not support");
        }
        return from.get(singularAttribute);
    }

    private static boolean isDeclaredOnStrictSubtypeOf(final From<?, ?> from, final Attribute<?, ?> fieldAttribute) {
        final Class<?> declaringType = fieldAttribute.getDeclaringType().getJavaType();
        return !declaringType.equals(from.getJavaType()) && from.getJavaType().isAssignableFrom(declaringType);
    }

    private static <T> Predicate getPropertyFilterPredicate(final CriteriaBuilder criteriaBuilder,
            final CommonAbstractCriteria query, final Root<T> root, SearchFilterRequestDto filterDto,
            Map<String, From> joinedAssociations, boolean refutedOidsOptedIn) {
        final FilterField filterField = FilterField.valueOf(filterDto.getFieldIdentifier());
        From from = getJoinedAssociation(root, joinedAssociations, filterField, filterDto.getCondition());

        // prepare filter values, expression and set filter characteristics
        List<Object> filterValues = preparePropertyFilterValues(filterDto, filterField);
        if (filterValues.isEmpty() && filterDto.getCondition() != FilterConditionOperator.EMPTY
                && filterDto.getCondition() != FilterConditionOperator.NOT_EMPTY) {
            throw new ValidationException("Filter for field " + filterField + " with operator "
                    + filterDto.getCondition() + " requires at least one value.");
        }

        // FREE_TEXT has no single fieldAttribute (it spans several columns) and CBOM_ASSET_SOURCE_CBOM's
        // fieldAttribute declares on Cbom, not on the crypto-asset root, so the generic from.get(...) below would
        // throw for it. Both are therefore built by dedicated branches before that generic resolution runs.
        if (filterField.getType() == SearchFieldTypeEnum.FREE_TEXT) {
            return getCryptoAssetFreeTextPredicate(criteriaBuilder, root, filterField, filterDto, filterValues,
                    refutedOidsOptedIn);
        }
        if (filterField == FilterField.CBOM_ASSET_SOURCE_CBOM) {
            return getCryptoAssetSourceCbomPredicate(criteriaBuilder, query, root, filterDto, filterValues);
        }

        // An expectedValue field compares one stored constant against the boolean the caller sends, so only EQUALS
        // and NOT_EQUALS are answerable -- exactly what SearchHelper advertises for it. The rest are refused here:
        // the boolean value prep below would otherwise fail on a valueless EMPTY, and NOT_EMPTY would read "any
        // value is set" -- which for the refuted-OID facet means any guard at all, not refutedness.
        if (filterField.getExpectedValue() != null) {
            if (filterDto.getCondition() != FilterConditionOperator.EQUALS
                    && filterDto.getCondition() != FilterConditionOperator.NOT_EQUALS) {
                throw new ValidationException("Condition " + filterDto.getCondition() + " is not supported for field "
                        + filterField + "; the field supports EQUALS and NOT_EQUALS.");
            }
            // The value prep below reads getValue().toString() through Boolean.parseBoolean, which turns a JSON
            // array ["true"] into "[true]" -> false and silently INVERTS the predicate -- after the facet's mere
            // presence has already disarmed the refuted-OID carve-outs for the whole request. Only a scalar
            // boolean is meaningful; everything else is refused before any predicate is built.
            Object rawValue = filterDto.getValue();
            boolean scalarBoolean = rawValue != null && !(rawValue instanceof Collection<?>)
                    && !rawValue.getClass().isArray()
                    && ("true".equalsIgnoreCase(rawValue.toString()) || "false".equalsIgnoreCase(rawValue.toString()));
            if (!scalarBoolean) {
                throw new ValidationException(
                        "Field " + filterField + " accepts a single boolean value, true or false.");
            }
        }

        Expression expression = null;
        if (filterField.getFieldAttribute() != null && !isCountOperator(filterDto.getCondition())) {
            expression = resolveFieldPath(from, filterField.getFieldAttribute());
        }

        boolean isJsonArray = false;
        if (filterField.getJsonPath() != null) {
            isJsonArray = isJsonArray(filterField);
            if (isJsonArray) {
                expression = criteriaBuilder
                        .function("jsonb_path_query_array", String.class,
                                resolveFieldPath(from, filterField.getFieldAttribute()),
                                criteriaBuilder.literal(getArrayJsonPath(filterField.getJsonPath())));
            } else {
                expression = switch (filterField.getJsonPath().length) {
                    case 1 -> criteriaBuilder
                            .function(JSONB_EXTRACT_PATH_TEXT_FUNCTION_NAME, String.class,
                                    resolveFieldPath(from, filterField.getFieldAttribute()),
                                    criteriaBuilder.literal(filterField.getJsonPath()[0]));
                    case 2 -> criteriaBuilder
                            .function(JSONB_EXTRACT_PATH_TEXT_FUNCTION_NAME, String.class,
                                    resolveFieldPath(from, filterField.getFieldAttribute()),
                                    criteriaBuilder.literal(filterField.getJsonPath()[0]),
                                    criteriaBuilder.literal(filterField.getJsonPath()[1]));
                    case 3 -> criteriaBuilder
                            .function(JSONB_EXTRACT_PATH_TEXT_FUNCTION_NAME, String.class,
                                    resolveFieldPath(from, filterField.getFieldAttribute()),
                                    criteriaBuilder.literal(filterField.getJsonPath()[0]),
                                    criteriaBuilder.literal(filterField.getJsonPath()[1]),
                                    criteriaBuilder.literal(filterField.getJsonPath()[2]));
                    case 4 -> criteriaBuilder
                            .function(JSONB_EXTRACT_PATH_TEXT_FUNCTION_NAME, String.class,
                                    resolveFieldPath(from, filterField.getFieldAttribute()),
                                    criteriaBuilder.literal(filterField.getJsonPath()[0]),
                                    criteriaBuilder.literal(filterField.getJsonPath()[1]),
                                    criteriaBuilder.literal(filterField.getJsonPath()[2]),
                                    criteriaBuilder.literal(filterField.getJsonPath()[3]));
                    default -> throw new ValidationException("Unexpected size of JSON path `%s`: %d"
                            .formatted(Arrays.toString(filterField.getJsonPath()), filterField.getJsonPath().length));
                };
            }
        } else if (filterField.getType().getExpressionClass() != null && filterField.getExpectedValue() == null) {
            if (expression == null) {
                throw new ValidationException("Invalid filter configuration: no expression for field " + filterField);
            }
            expression = ((JpaExpression) expression).cast(filterField.getType().getExpressionClass());
        }

        boolean multipleValues = filterValues.size() > 1;
        boolean hasParent = !filterField.getJoinAttributes().isEmpty()
                && filterField.getFieldResource() != Resource.USER; // workaround for owner => fieldResource = USER
        boolean isParentCollection = hasParent && filterField.getJoinAttributes().getLast().isCollection();
        PluralAttribute.CollectionType parentCollectionType = hasParent && isParentCollection
                ? ((PluralAttribute) filterField.getJoinAttributes().getLast()).getCollectionType()
                : null;

        // workaround for set attributes associations
        if (parentCollectionType == PluralAttribute.CollectionType.SET) {
            hasParent = false;
        }

        Predicate predicate = null;
        FilterConditionOperator conditionOperator = filterDto.getCondition();

        // update condition operator if filter is based on comparing field to expected value
        if (filterField.getExpectedValue() != null) {
            final Boolean booleanValue = Boolean.parseBoolean(filterDto.getValue().toString());
            if (conditionOperator == FilterConditionOperator.EQUALS && Boolean.FALSE.equals(booleanValue)) {
                conditionOperator = FilterConditionOperator.NOT_EQUALS;
            } else if (conditionOperator == FilterConditionOperator.NOT_EQUALS && Boolean.FALSE.equals(booleanValue)) {
                conditionOperator = FilterConditionOperator.EQUALS;
            }
        }
        final LocalDateTime now = LocalDateTime.now();
        boolean bitEnumProperty = filterField.getEnumClass() != null
                && BitMaskEnum.class.isAssignableFrom(filterField.getEnumClass());
        if (expression == null && !isCountOperator(conditionOperator)) {
            throw new ValidationException("Invalid filter configuration: no expression for field " + filterField
                    + " with operator " + conditionOperator);
        }
        final Expression finalExpression = expression;
        switch (conditionOperator) {
            case EQUALS -> {
                if (bitEnumProperty) {
                    predicate = criteriaBuilder
                            .notEqual(getBitwiseEqualExpression(filterValues.getFirst(), expression, criteriaBuilder),
                                    0);
                } else if (isJsonArray) {
                    predicate = criteriaBuilder
                            .isTrue(getJsonArrayEqualsExpression(criteriaBuilder, expression,
                                    filterValues.getFirst().toString()));
                } else if (filterField.isNativeArrayField()) {
                    predicate = getNativeArrayEqualsExpression(criteriaBuilder, filterValues, finalExpression);
                } else {
                    predicate = multipleValues
                            ? expression.in(filterValues)
                            : criteriaBuilder.equal(expression, filterValues.getFirst());
                }
            }
            case NOT_EQUALS -> {
                if (bitEnumProperty) {
                    predicate = criteriaBuilder
                            .equal(getBitwiseEqualExpression(filterValues.getFirst(), expression, criteriaBuilder), 0);
                } else if (isJsonArray) {
                    predicate = criteriaBuilder
                            .isFalse(getJsonArrayEqualsExpression(criteriaBuilder, expression,
                                    filterValues.getFirst().toString()));
                } else if (filterField.isNativeArrayField()) {
                    predicate = filterField.getJoinAttributes().isEmpty()
                            ? getNativeArrayNotEqualsExpression(criteriaBuilder, filterValues, finalExpression,
                                    expression)
                            : buildNativeArrayNotExistsPredicate(criteriaBuilder, query, root, filterField,
                                    filterValues, ARRAY_CONTAINS_FUNCTION_NAME);
                } else {
                    // hack how to filter out correctly Has private key property filter for certificate. Needs to find
                    // correct solution for SET attributes predicates!
                    if (filterField.getExpectedValue() != null && filterField == FilterField.PRIVATE_KEY) {
                        predicate = criteriaBuilder
                                .or(criteriaBuilder
                                        .and(criteriaBuilder.notEqual(expression, filterValues.getFirst()),
                                                criteriaBuilder.equal(expression, filterValues.getFirst())),
                                        criteriaBuilder.isNull(expression));
                    } else {
                        predicate = filterField.getFieldResource() == Resource.GROUP
                                ? getGroupNotExistPredicate(criteriaBuilder, query, root,
                                        filterField.getFieldAttribute(), filterValues, filterField.getRootResource())
                                : criteriaBuilder
                                        .or(getNotPresentPredicate(criteriaBuilder, from, expression, hasParent,
                                                isParentCollection, false, isJsonArray),
                                                multipleValues
                                                        ? criteriaBuilder.not(expression.in(filterValues))
                                                        : criteriaBuilder
                                                                .notEqual(expression, filterValues.getFirst()));
                    }
                }
            }
            case STARTS_WITH -> predicate = criteriaBuilder.like(expression, filterValues.getFirst() + "%");
            case ENDS_WITH -> predicate = criteriaBuilder.like(expression, "%" + filterValues.getFirst());
            case CONTAINS -> {
                if (filterField.isNativeArrayField()) {
                    predicate = getNativeArrayContainsExpression(criteriaBuilder, filterValues, finalExpression);
                } else {
                    predicate = criteriaBuilder.like(expression, "%" + filterValues.getFirst() + "%");
                }
            }
            case NOT_CONTAINS -> {
                if (filterField.isNativeArrayField()) {
                    predicate = filterField.getJoinAttributes().isEmpty()
                            ? getNativeArrayNotContainsExpression(criteriaBuilder, filterValues, finalExpression,
                                    expression)
                            : buildNativeArrayNotExistsPredicate(criteriaBuilder, query, root, filterField,
                                    filterValues, ARRAY_ITEM_CONTAINS_FUNCTION_NAME);
                } else {
                    predicate = criteriaBuilder
                            .or(getNotPresentPredicate(criteriaBuilder, from, expression, hasParent, isParentCollection,
                                    false, isJsonArray),
                                    criteriaBuilder.notLike(expression, "%" + filterValues.getFirst() + "%"));
                }
            }
            case EMPTY -> {
                if (filterField.isNativeArrayField()) {
                    predicate = criteriaBuilder
                            .or(criteriaBuilder.isNull(expression), criteriaBuilder
                                    .equal(criteriaBuilder.function("cardinality", Integer.class, expression), 0));
                } else {
                    predicate = getNotPresentPredicate(criteriaBuilder, from, expression, hasParent, isParentCollection,
                            bitEnumProperty, isJsonArray);
                }
            }
            case NOT_EMPTY -> {
                if (filterField.isNativeArrayField()) {
                    predicate = criteriaBuilder
                            .and(criteriaBuilder.isNotNull(expression), criteriaBuilder
                                    .greaterThan(criteriaBuilder.function("cardinality", Integer.class, expression),
                                            0));
                } else {
                    predicate = criteriaBuilder
                            .not(getNotPresentPredicate(criteriaBuilder, from, expression, hasParent,
                                    isParentCollection, bitEnumProperty, isJsonArray));
                }
            }
            case GREATER -> predicate = criteriaBuilder
                    .greaterThan(expression, (Expression) criteriaBuilder.literal(filterValues.getFirst()));
            case GREATER_OR_EQUAL -> predicate = criteriaBuilder
                    .greaterThanOrEqualTo(expression, (Expression) criteriaBuilder.literal(filterValues.getFirst()));
            case LESSER -> predicate = criteriaBuilder
                    .lessThan(expression, (Expression) criteriaBuilder.literal(filterValues.getFirst()));
            case LESSER_OR_EQUAL -> predicate = criteriaBuilder
                    .lessThanOrEqualTo(expression, (Expression) criteriaBuilder.literal(filterValues.getFirst()));
            case IN_PAST -> {
                Duration duration = (Duration) filterValues.getFirst();
                predicate = criteriaBuilder
                        .between(expression,
                                now
                                        .minus(Period.of(duration.getYears(), duration.getMonths(), duration.getDays()))
                                        .minusHours(duration.getHours())
                                        .minusMinutes(duration.getMinutes())
                                        .minusSeconds(duration.getSeconds()),
                                now);
            }
            case IN_NEXT -> {
                Duration duration = (Duration) filterValues.getFirst();
                predicate = criteriaBuilder
                        .between(expression, now,
                                now
                                        .plus(Period.of(duration.getYears(), duration.getMonths(), duration.getDays()))
                                        .plusHours(duration.getHours())
                                        .plusMinutes(duration.getMinutes())
                                        .plusSeconds(duration.getSeconds()));
            }
            case MATCHES -> {
                validateRegexForDbQuery(filterValues.getFirst().toString());
                predicate = criteriaBuilder
                        .equal(criteriaBuilder
                                .function(TEXTREGEXEQ_FUNCTION_NAME, Boolean.class, expression,
                                        criteriaBuilder.literal(filterValues.getFirst())),
                                true);
            }
            case NOT_MATCHES -> {
                validateRegexForDbQuery(filterValues.getFirst().toString());
                predicate = criteriaBuilder
                        .equal(criteriaBuilder
                                .function(TEXTREGEXEQ_FUNCTION_NAME, Boolean.class, expression,
                                        criteriaBuilder.literal(filterValues.getFirst())),
                                false);
            }
            case COUNT_EQUAL -> predicate = criteriaBuilder.equal(criteriaBuilder.size(from), filterValues.getFirst());
            case COUNT_NOT_EQUAL -> predicate = criteriaBuilder
                    .not(criteriaBuilder.equal(criteriaBuilder.size(from), filterValues.getFirst()));
            case COUNT_GREATER_THAN -> {
                try {
                    predicate = criteriaBuilder
                            .greaterThan(criteriaBuilder.size(from), (Expression) criteriaBuilder
                                    .literal(Integer.parseInt(filterValues.getFirst().toString())));
                } catch (NumberFormatException e) {
                    throw new ValidationException(
                            "Filter field value " + filterValues.getFirst() + " cannot be parsed as an Integer.");
                }
            }
            case COUNT_LESS_THAN -> {
                try {
                    predicate = criteriaBuilder
                            .lessThan(criteriaBuilder.size(from), (Expression) criteriaBuilder
                                    .literal(Integer.parseInt(filterValues.getFirst().toString())));
                } catch (NumberFormatException e) {
                    throw new ValidationException(
                            "Filter field value " + filterValues.getFirst() + " cannot be parsed as an Integer.");
                }
            }

            default -> throw new ValidationException("Unexpected value: " + conditionOperator);
        }

        // A refuted OID must answer OID value predicates exactly as an absent one would: the stored value
        // is auditable, but it must never decide membership. Conditions a NULL oid satisfies
        // (the or(isNull, ...) negatives) admit refuted rows too; conditions a NULL oid can never satisfy
        // exclude them. EMPTY/NOT_EMPTY stay untouched -- that an OID was recorded is a true fact.
        if (filterField == FilterField.CBOM_ASSET_OID && !refutedOidsOptedIn) {
            if (OID_CONDITIONS_A_NULL_OID_SATISFIES.contains(conditionOperator)) {
                predicate = criteriaBuilder.or(predicate, oidRefuted(criteriaBuilder, from));
            } else if (OID_CONDITIONS_A_NULL_OID_NEVER_SATISFIES.contains(conditionOperator)) {
                predicate = criteriaBuilder.and(predicate, oidNotRefuted(criteriaBuilder, from));
            }
        }
        return predicate;
    }

    /**
     * Matches a single text input, case-insensitively, across the crypto-asset name and oid columns at once. A refuted
     * oid is excluded from its side of the match unless the caller opted into the refuted-OID facet, so the row stays
     * findable through its name but the neutralized oid cannot answer the query.
     *
     * <p>
     * Index note, superseding migration V202608271000's rationale comment ("FilterPredicatesBuilder never emits
     * lower()" -- true when the migration shipped, falsified by this method; the applied file is Flyway-checksum
     * frozen, so the correction lives here). The conclusion still holds: infix {@code %x%} LIKE is unservable by any
     * btree, so free text is a sequential scan by design in v1. Measured while confirming: prefix LIKE (STARTS_WITH) is
     * equally unservable under a non-C collation without {@code text_pattern_ops}, so the upgrade path if this surface
     * gets hot is a trigram GIN on lower(name)/lower(oid) for infix plus {@code text_pattern_ops} btrees for prefix --
     * a new indexing migration, never an edit to the applied one.
     */
    private static <T> Predicate getCryptoAssetFreeTextPredicate(CriteriaBuilder criteriaBuilder, Root<T> root,
            FilterField filterField, SearchFilterRequestDto filterDto, List<Object> filterValues,
            boolean refutedOidsOptedIn) {
        if (filterField != FilterField.CBOM_ASSET_FREE_TEXT) {
            throw new ValidationException("Free-text filter is not defined for field " + filterField + ".");
        }
        if (filterDto.getCondition() != FilterConditionOperator.CONTAINS) {
            throw new ValidationException(
                    "Free-text filter for field " + filterField + " supports only the CONTAINS operator.");
        }
        if (filterValues.size() > 1) {
            throw new ValidationException("Free-text filter for field " + filterField + " accepts a single value.");
        }

        // Bound as a parameter, never a literal: an inlined pattern lands verbatim in the SQL statement text --
        // Postgres server logs, pg_stat_statements -- and people paste secrets into search boxes. lower() stays on
        // the SQL side so both operands fold under the database's collation, not two different case rules.
        Expression<String> pattern = criteriaBuilder
                .lower(((HibernateCriteriaBuilder) criteriaBuilder)
                        .value("%" + escapeLikeWildcards(filterValues.getFirst().toString()) + "%"));
        Predicate nameMatches = criteriaBuilder
                .like(criteriaBuilder.lower(root.get(CryptoAsset_.NAME)), pattern, LIKE_ESCAPE_CHAR);
        Predicate oidMatches = criteriaBuilder
                .like(criteriaBuilder.lower(root.get(CryptoAsset_.OID)), pattern, LIKE_ESCAPE_CHAR);
        if (!refutedOidsOptedIn) {
            oidMatches = criteriaBuilder.and(oidMatches, oidNotRefuted(criteriaBuilder, root));
        }
        return criteriaBuilder.or(nameMatches, oidMatches);
    }

    /**
     * LIKE's {@code %}, {@code _} and the escape character itself, escaped so free-text input matches literally. The
     * generic CONTAINS on single columns leaves wildcards active (a platform-wide trait predating this field); the
     * free-text box is new surface, and a search box promises literal matching.
     */
    private static String escapeLikeWildcards(String value) {
        return value.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_");
    }

    private static Predicate oidNotRefuted(CriteriaBuilder cb, From<?, ?> from) {
        Path<CryptoAssetIdentityGuard> guard = from.get(CryptoAsset_.IDENTITY_GUARD);
        return cb.or(cb.isNull(guard), cb.notEqual(guard, CryptoAssetIdentityGuard.REFUTED_OID));
    }

    private static Predicate oidRefuted(CriteriaBuilder cb, From<?, ?> from) {
        return cb.equal(from.get(CryptoAsset_.IDENTITY_GUARD), CryptoAssetIdentityGuard.REFUTED_OID);
    }

    /**
     * Matches through an EXISTS subquery against {@code crypto_asset_source}, never a join: the uuid page query this
     * predicate feeds carries no DISTINCT, so a join would repeat a row that has several matching sources.
     */
    private static <T> Predicate getCryptoAssetSourceCbomPredicate(CriteriaBuilder cb, CommonAbstractCriteria query,
            Root<T> root, SearchFilterRequestDto filterDto, List<Object> filterValues) {
        Subquery<Integer> subquery = query.subquery(Integer.class);
        Root<CryptoAssetSource> source = subquery.from(CryptoAssetSource.class);
        Predicate correlation = cb
                .equal(source.get(CryptoAssetSource_.assetUuid), root.get(UniquelyIdentified_.uuid.getName()));
        FilterConditionOperator condition = filterDto.getCondition();
        switch (condition) {
            case EQUALS, NOT_EQUALS -> {
                Join cbom = source.join(CryptoAssetSource_.cbom);
                subquery.select(cb.literal(1)).where(correlation, cbom.get(Cbom_.serialNumber).in(filterValues));
                return condition == FilterConditionOperator.EQUALS ? cb.exists(subquery) : cb.not(cb.exists(subquery));
            }
            case EMPTY, NOT_EMPTY -> {
                subquery.select(cb.literal(1)).where(correlation);
                return condition == FilterConditionOperator.NOT_EMPTY
                        ? cb.exists(subquery)
                        : cb.not(cb.exists(subquery));
            }
            default -> throw new ValidationException("Unexpected condition " + condition + " for filter field "
                    + FilterField.CBOM_ASSET_SOURCE_CBOM + ".");
        }
    }

    public static boolean isJsonArray(FilterField filterField) {
        return Arrays.stream(filterField.getJsonPath()).anyMatch(pathPart -> pathPart.contains("*"));
    }

    private static String getArrayJsonPath(String[] jsonPath) {
        StringBuilder stringBuilder = new StringBuilder("$");
        for (String pathPart : jsonPath) {
            stringBuilder.append(".");
            stringBuilder.append(pathPart);
        }
        return stringBuilder.toString();
    }

    private static Expression<Boolean> getJsonArrayEqualsExpression(CriteriaBuilder criteriaBuilder,
            Expression expression, String filterValue) {
        return criteriaBuilder
                .function(PostgresFunctionContributor.JSONB_CONTAINS, Boolean.class, expression,
                        criteriaBuilder.literal("[\"%s\"]".formatted(filterValue)));
    }

    private static Predicate getNativeArrayEqualsExpression(CriteriaBuilder criteriaBuilder, List<Object> filterValues,
            Expression finalExpression) {
        List<Predicate> nativeArrayPredicates = filterValues
                .stream()
                .map(value -> criteriaBuilder
                        .isTrue(criteriaBuilder
                                .function(ARRAY_CONTAINS_FUNCTION_NAME, Boolean.class,
                                        criteriaBuilder.literal(value.toString()), finalExpression)))
                .toList();
        return nativeArrayPredicates.size() == 1
                ? nativeArrayPredicates.getFirst()
                : criteriaBuilder.or(nativeArrayPredicates.toArray(new Predicate[0]));
    }

    private static Predicate getNativeArrayNotEqualsExpression(CriteriaBuilder criteriaBuilder,
            List<Object> filterValues, Expression finalExpression, Expression expression) {
        Predicate[] nativeArrayNotContainsPredicates = filterValues
                .stream()
                .map(value -> criteriaBuilder
                        .isFalse(criteriaBuilder
                                .function(ARRAY_CONTAINS_FUNCTION_NAME, Boolean.class,
                                        criteriaBuilder.literal(value.toString()), finalExpression)))
                .toArray(Predicate[]::new);
        return criteriaBuilder
                .or(criteriaBuilder.isNull(expression), criteriaBuilder.and(nativeArrayNotContainsPredicates));
    }

    private static Predicate getNativeArrayContainsExpression(CriteriaBuilder criteriaBuilder,
            List<Object> filterValues, Expression finalExpression) {
        List<Predicate> nativeArrayContainsPredicates = filterValues
                .stream()
                .map(value -> criteriaBuilder
                        .isTrue(criteriaBuilder
                                .function(ARRAY_ITEM_CONTAINS_FUNCTION_NAME, Boolean.class,
                                        criteriaBuilder.literal(value.toString()), finalExpression)))
                .toList();

        // Multi-value CONTAINS should match when any filter value is present in array items
        return nativeArrayContainsPredicates.size() == 1
                ? nativeArrayContainsPredicates.getFirst()
                : criteriaBuilder.or(nativeArrayContainsPredicates.toArray(new Predicate[0]));
    }

    private static Predicate getNativeArrayNotContainsExpression(CriteriaBuilder criteriaBuilder,
            List<Object> filterValues, Expression finalExpression, Expression expression) {
        Predicate[] nativeArrayNotContainsPredicates = filterValues
                .stream()
                .map(value -> criteriaBuilder
                        .isFalse(criteriaBuilder
                                .function(ARRAY_ITEM_CONTAINS_FUNCTION_NAME, Boolean.class,
                                        criteriaBuilder.literal(value.toString()), finalExpression)))
                .toArray(Predicate[]::new);

        // Keep existing NOT_* semantics: include null arrays as not containing searched values
        return criteriaBuilder
                .or(criteriaBuilder.isNull(expression), criteriaBuilder.and(nativeArrayNotContainsPredicates));
    }

    // NOT EXISTS subquery is required here instead of a per-row predicate because the array field is accessed
    // through a collection join (e.g. connector → connector_interface), producing multiple rows per root entity.
    // A per-row check would incorrectly include an entity if any of its joined rows has a null/non-matching
    // array, even when another row does contain the value. NOT EXISTS ensures the entity is excluded whenever
    // any of its joined rows satisfies the positive condition.
    private static <T> Predicate buildNativeArrayNotExistsPredicate(CriteriaBuilder criteriaBuilder,
            CommonAbstractCriteria query, Root<T> root, FilterField filterField, List<Object> filterValues,
            String functionName) {
        Predicate[] notExistsPredicates = filterValues.stream().map(value -> {
            Subquery<Integer> subquery = query.subquery(Integer.class);
            From subFrom = subquery.correlate(root);
            for (Attribute attr : filterField.getJoinAttributes()) {
                subFrom = subFrom.join(attr.getName(), JoinType.INNER);
            }
            subquery
                    .select(criteriaBuilder.literal(1))
                    .where(criteriaBuilder
                            .isTrue(criteriaBuilder
                                    .function(functionName, Boolean.class, criteriaBuilder.literal(value.toString()),
                                            resolveFieldPath(subFrom, filterField.getFieldAttribute()))));
            return criteriaBuilder.not(criteriaBuilder.exists(subquery));
        }).toArray(Predicate[]::new);
        return notExistsPredicates.length == 1 ? notExistsPredicates[0] : criteriaBuilder.and(notExistsPredicates);
    }

    private static Expression<?> getBitwiseEqualExpression(Object bit, Expression expression,
            CriteriaBuilder criteriaBuilder) {
        Expression<?> mask = criteriaBuilder.literal(bit);
        return criteriaBuilder.function(PostgresFunctionContributor.BIT_AND_FUNCTION, Integer.class, expression, mask);
    }

    private static void validateRegexForDbQuery(String regex) {
        try {
            Pattern.compile(regex);
        } catch (PatternSyntaxException e) {
            throw new ValidationException("Input is not a valid regex: " + e.getMessage());
        }

        // Literals \Q, \R, \G, ... are forbidden, but \\Q, \\R, \\G, ... should stay allowed
        if (containsUnescapedSlashFollowedBy(regex, "QRGhHzXV")) {
            throw new ValidationException(
                    "Literal quote sequences \\Q, \\R, \\G, \\h, \\H, \\z, \\X, \\V are not supported in PostgreSQL POSIX regex");
        }
    }

    private static boolean containsUnescapedSlashFollowedBy(String s, String chars) {
        for (int i = 0; i < s.length() - 1; i++) {
            if (s.charAt(i) != '\\') {
                continue;
            }
            char next = s.charAt(i + 1);
            if (chars.indexOf(next) < 0) {
                continue;
            }
            // count backslashes immediately before s.charAt(i)
            int j = i - 1;
            int count = 0;
            while (j >= 0 && s.charAt(j) == '\\') {
                count++;
                j--;
            }
            // if count is even -> this backslash is not escaped
            if ((count % 2) == 0) {
                return true;
            }
        }
        return false;
    }

    private static <T> From getJoinedAssociation(Root<T> root, Map<String, From> joinedAssociations,
            FilterField filterField, FilterConditionOperator condition) {
        From from = root;
        From joinedAssociation;
        String associationFullPath = null;
        List<Attribute> joinAttributes = filterField.getJoinAttributes();
        int lastIndex = joinAttributes.size();

        // If count operator, find last collection attribute index
        if (isCountOperator(condition)) {
            lastIndex = getLastCollectionIndex(joinAttributes, lastIndex);
        }

        for (int i = 0; i < lastIndex; i++) {
            Attribute joinAttribute = joinAttributes.get(i);

            associationFullPath = associationFullPath == null
                    ? joinAttribute.getName()
                    : associationFullPath + "." + joinAttribute.getName();

            joinedAssociation = joinedAssociations.get(associationFullPath);

            if (joinedAssociation != null) {
                from = joinedAssociation;
            } else {
                from = from.join(joinAttribute.getName(), JoinType.LEFT);
                joinedAssociations.put(associationFullPath, from);
            }
        }
        return from;
    }

    public static int getLastCollectionIndex(List<Attribute> joinAttributes, int lastIndex) {
        for (int i = joinAttributes.size() - 1; i >= 0; i--) {
            if (joinAttributes.get(i).isCollection()) {
                lastIndex = i + 1;
                break;
            }
        }
        return lastIndex;
    }

    private static boolean isCountOperator(FilterConditionOperator condition) {
        return condition == FilterConditionOperator.COUNT_EQUAL || condition == FilterConditionOperator.COUNT_NOT_EQUAL
                || condition == FilterConditionOperator.COUNT_GREATER_THAN
                || condition == FilterConditionOperator.COUNT_LESS_THAN;
    }

    private static List<Object> preparePropertyFilterValues(final SearchFilterRequestDto filterDto,
            final FilterField filterField) {
        Serializable filterValue = filterDto.getValue();

        if (filterValue == null) {
            return List.of();
        }

        final List<Object> preparedFilterValues = new ArrayList<>();
        List<Object> filterValues = filterValue instanceof List<?> ? (List<Object>) filterValue : List.of(filterValue);
        for (Object value : filterValues) {
            Object preparedFilterValue = null;
            if (filterField.getEnumClass() != null && !isCountOperator(filterDto.getCondition())) {
                if (BitMaskEnum.class.isAssignableFrom(filterField.getEnumClass())) {
                    final BitMaskEnum enumValue = (BitMaskEnum) findEnumByCustomValue(value,
                            filterField.getEnumClass());
                    if (enumValue != null) {
                        preparedFilterValue = enumValue.getBit();
                    }
                } else {
                    preparedFilterValue = findEnumByCustomValue(value, filterField.getEnumClass());
                    if (preparedFilterValue == null && filterField.isNativeArrayField()) {
                        throw new ValidationException(
                                "Unknown filter value '%s' for field %s".formatted(value, filterField));
                    }
                }
            } else {
                String stringValue = value.toString();
                if (filterField.getType() == SearchFieldTypeEnum.BOOLEAN) {
                    var boolValue = Boolean.parseBoolean(stringValue);
                    if (filterField.getExpectedValue() == null) {
                        preparedFilterValue = boolValue;
                    } else {
                        preparedFilterValue = filterField.getExpectedValue();
                    }
                } else if (filterField.getType() == SearchFieldTypeEnum.NUMBER) {
                    try {
                        preparedFilterValue = stringValue.contains(".")
                                ? Float.parseFloat(stringValue)
                                : Integer.parseInt(stringValue);
                    } catch (NumberFormatException e) {
                        throw new ValidationException(
                                "Filter field value " + stringValue + " cannot be parsed as a Number.");
                    }
                } else if (filterDto.getCondition() == FilterConditionOperator.IN_PAST
                        || filterDto.getCondition() == FilterConditionOperator.IN_NEXT) {
                    try {
                        if (filterField.getType() == SearchFieldTypeEnum.DATE) {
                            stringValue = extractDateFromDuration(stringValue);
                        }
                        preparedFilterValue = DatatypeFactory.newInstance().newDuration(stringValue);
                    } catch (Exception e) {
                        throw new ValidationException(
                                "Filter field value " + stringValue + " cannot be parsed to a Duration.");
                    }
                } else if (filterField.getType() == SearchFieldTypeEnum.DATE) {
                    preparedFilterValue = LocalDate.parse(stringValue);
                } else if (filterField.getType() == SearchFieldTypeEnum.DATETIME) {
                    preparedFilterValue = LocalDateTime
                            .parse(stringValue, DateTimeFormatter
                                    .ofPattern(
                                            "[yyyy-MM-dd'T'HH:mm:ss.SSSXXX][yyyy-MM-dd'T'HH:mm:ssXXX][yyyy-MM-dd'T'HH:mmXXX]"));
                } else {
                    preparedFilterValue = stringValue;
                }
            }

            preparedFilterValues.add(preparedFilterValue);
        }

        return preparedFilterValues;
    }

    private static String extractDateFromDuration(String stringValue) {
        int index = stringValue.indexOf('T');
        stringValue = (index != -1) ? stringValue.substring(0, index) : stringValue;
        return stringValue;
    }

    private static Predicate getGroupNotExistPredicate(final CriteriaBuilder criteriaBuilder,
            final CommonAbstractCriteria query, Root originalRoot, Attribute fieldAttribute, List<Object> filterValues,
            Resource resource) {
        final Subquery<Integer> subquery = query.subquery(Integer.class);
        final Root<GroupAssociation> subqueryRoot = subquery.from(GroupAssociation.class);
        final Join joinGroup = subqueryRoot.join(GroupAssociation_.group);
        subquery
                .select(criteriaBuilder.literal(1))
                .where(criteriaBuilder.equal(subqueryRoot.get(ResourceObjectAssociation_.resource), resource),
                        criteriaBuilder
                                .equal(subqueryRoot.get(ResourceObjectAssociation_.objectUuid),
                                        resource == Resource.CRYPTOGRAPHIC_KEY
                                                ? originalRoot.get(CryptographicKeyItem_.keyUuid)
                                                : originalRoot.get(UniquelyIdentified_.uuid)),
                        resolveFieldPath(joinGroup, fieldAttribute).in(filterValues));

        return criteriaBuilder.not(criteriaBuilder.exists(subquery));
    }

    private static Predicate getNotPresentPredicate(final CriteriaBuilder criteriaBuilder, From from,
            Expression expression, boolean hasParent, boolean isParentCollection, boolean isEnumList,
            boolean isJsonArray) {
        if (isEnumList) {
            return criteriaBuilder.equal(expression, 0);
        }

        if (isJsonArray) {
            return criteriaBuilder
                    .or(criteriaBuilder.equal(expression, criteriaBuilder.literal(EMPTY_JSON_ARRAY)),
                            criteriaBuilder.isNull(expression),
                            criteriaBuilder.equal(expression, criteriaBuilder.literal(NULL_JSON_ARRAY)));
        }
        if (!hasParent) {
            return criteriaBuilder.isNull(expression);
        }
        if (!isParentCollection) {
            return criteriaBuilder.isNull(from);
        }

        return criteriaBuilder.isEmpty(from);
    }

    private static Object findEnumByCustomValue(Object valueObject, final Class<? extends IPlatformEnum> enumClass) {
        Optional<? extends IPlatformEnum> enumItem = Arrays
                .stream(enumClass.getEnumConstants())
                .filter(enumValue -> enumValue.getCode().equals(valueObject.toString()))
                .findFirst();
        return enumItem.orElse(null);
    }

    public static Join prepareJoin(final Root root, final String joinPath) {
        final StringTokenizer stz = new StringTokenizer(joinPath, ".");
        Join join = root.join(stz.nextToken(), JoinType.LEFT);
        while (stz.hasMoreTokens()) {
            join = join.join(stz.nextToken(), JoinType.LEFT);
        }
        return join;
    }

    public static Expression<?> prepareExpression(final From from, final String attributeName) {
        final StringTokenizer stz = new StringTokenizer(attributeName, ".");
        Path path = from.get(stz.nextToken());
        while (stz.hasMoreTokens()) {
            path = path.get(stz.nextToken());
        }
        return path;
    }

    public static Query getAllValuesOfProperty(String property, Resource resource, EntityManager entityManager) {
        Class resourceClass = ResourceToClass.getClassByResource(resource);
        return entityManager.createQuery("SELECT DISTINCT " + property + " FROM " + resourceClass.getName());
    }

    public static Predicate constructFilterForJobHistory(final CriteriaBuilder cb, final Root<ScheduledJobHistory> root,
            final UUID scheduledJobUuid) {
        final Expression<?> expressionPath = prepareExpression(root, "scheduledJobUuid");
        return cb.equal(expressionPath, scheduledJobUuid);
    }

    public static String buildPathToProperty(List<Attribute> joinAttributes, Attribute fieldAttribute) {
        StringBuilder pathToPropertyBuilder = new StringBuilder();

        if (joinAttributes != null && !joinAttributes.isEmpty()) {
            // join attribute names with a dot
            pathToPropertyBuilder
                    .append(joinAttributes.stream().map(Attribute::getName).collect(Collectors.joining(".")));
        }

        if (fieldAttribute != null) {
            if (!pathToPropertyBuilder.isEmpty()) {
                pathToPropertyBuilder.append(".");
            }
            pathToPropertyBuilder.append(fieldAttribute.getName());
        }
        return pathToPropertyBuilder.toString();
    }

    /**
     * The predicates that pin a content row to one attribute definition and to one object: the definition's type,
     * content type and name, and the object the content is attached to. Shared by the filter predicate and the sort key
     * so the two cannot disagree about which rows belong to a field.
     */
    private static <T> List<Predicate> attributeCorrelationPredicates(final CriteriaBuilder criteriaBuilder,
            final Root<T> root, final Root<AttributeContent2Object> subqueryRoot, final Join joinDefinition,
            final AttributeType attributeType, final AttributeContentType contentType, final String attributeName,
            final Resource resource, final String objectUuidPath) {
        return List
                .of(criteriaBuilder.equal(joinDefinition.get(AttributeDefinition_.type), attributeType),
                        criteriaBuilder.equal(joinDefinition.get(AttributeDefinition_.contentType), contentType),
                        criteriaBuilder.equal(joinDefinition.get(AttributeDefinition_.name), attributeName),
                        criteriaBuilder.equal(subqueryRoot.get(AttributeContent2Object_.objectType), resource),
                        criteriaBuilder
                                .equal(subqueryRoot.get(AttributeContent2Object_.objectUuid),
                                        root.get(objectUuidPath)));
    }

    /**
     * The resource an object's attribute content is stored under. Key items carry the key's attributes, so a key item
     * root resolves to {@code CRYPTOGRAPHIC_KEY} rather than to a resource of its own.
     *
     * <p>
     * A place for improvement is to consolidate the resource attribute content is stored under, so this mapping is not
     * needed at all.
     */
    private static <T> Resource attributeResourceOf(final Root<T> root) {
        return root.getJavaType().equals(CryptographicKeyItem.class)
                ? Resource.CRYPTOGRAPHIC_KEY
                : ResourceToClass.getResourceByClass(root.getJavaType());
    }

    /**
     * Which uuid of the root the content is keyed by. For a key item, meta attributes are attached to the item while
     * custom and data attributes are attached to the key it belongs to.
     *
     * <p>
     * Decided from the root rather than from the resource, because the key uuid is a column of the key item and of
     * nothing else: a root that is not one has no such path to read, whatever resource its content is filed under.
     */
    private static <T> String attributeObjectUuidPath(final Root<T> root, final AttributeType attributeType) {
        return root.getJavaType().equals(CryptographicKeyItem.class)
                && (attributeType == AttributeType.CUSTOM || attributeType == AttributeType.DATA)
                        ? CryptographicKeyItem_.keyUuid.getName()
                        : UniquelyIdentified_.uuid.getName();
    }

    /**
     * A scalar sort key carrying the value of one attribute-sourced field for one row.
     *
     * <p>
     * Filtering an attribute is order-agnostic and so is expressed as {@code EXISTS}, which yields no value to order
     * by. Ordering needs the value itself, so this is a correlated scalar subquery instead: the same definition and
     * object correlation as the filter, extracted from the stored json with the same {@code jsonb_extract_path_text}
     * and the same per-content-type cast, so a column sorts by what the cell displays.
     *
     * <p>
     * An attribute may hold several values for one object, which leaves the key ambiguous. The subquery therefore
     * orders by definition and then by {@code item_order} and takes the first row - the same order the projection query
     * reads a page of values in - so a multi-valued attribute sorts on the value the cell shows first, and two
     * identical requests cannot pick differently among the definitions one attribute name may map to. A row with no
     * value for the field yields no row and so a null key, which is ordered last in both directions by the caller
     * rather than being dropped.
     *
     * <p>
     * Ordering reads a value, so it is gated like the projection that renders one: encrypted content is skipped, a
     * disabled custom definition is skipped, and the caller's custom-attribute permissions narrow which definitions are
     * readable at all. Whether the field may be ordered on - visible, not secret, not a code block - is settled before
     * this by {@code ListingSortResolver} against the resource's published catalogue.
     */
    public static <T> Expression<?> getAttributeSortKey(final CriteriaBuilder criteriaBuilder,
            final CommonAbstractCriteria query, final Root<T> root, final SortSpecification sort) {
        final FilterFieldSource fieldSource = sort.fieldSource();
        final String fieldIdentifier = sort.fieldIdentifier();
        final AttributeType attributeType = fieldSource == null ? null : fieldSource.getAttributeType();
        if (attributeType == null) {
            throw new ValidationException(
                    ValidationError.create("Sort field source %s names no attribute type.".formatted(fieldSource)));
        }
        // The caller's attribute permissions are what keeps ordering from reading further than projection does, so a
        // specification that was never resolved against them is refused rather than run unrestricted.
        final Supplier<CustomAttributeContentFilter> contentFilterSource = sort.attributeContentFilterSource();
        if (contentFilterSource == null) {
            throw new ValidationException(ValidationError
                    .create("Ordering by %s was not resolved against the caller's attribute permissions."
                            .formatted(fieldIdentifier)));
        }

        final AttributeFieldIdentifier identifier = AttributeFieldIdentifier.parse(fieldIdentifier);
        if (identifier == null) {
            throw new ValidationException(ValidationError
                    .create("Sort field identifier %s does not name an attribute.".formatted(fieldIdentifier)));
        }
        final String attributeName = identifier.attributeName();
        final AttributeContentType contentType = identifier.contentType();
        if (contentType == null) {
            throw new ValidationException(ValidationError
                    .create("Unknown attribute content type %s in sort field identifier %s."
                            .formatted(identifier.contentTypeName(), fieldIdentifier)));
        }

        // The resource the listing selects, which the catalogue was read from; the root is only a fallback for a
        // caller that built a specification without one, and maps to nothing for an entity outside ResourceToClass.
        final Resource resource = sort.resource() == null ? attributeResourceOf(root) : sort.resource();
        final String objectUuidPath = attributeObjectUuidPath(root, attributeType);

        // Typed to the value's own class rather than to Object: the aggregate the grouped ordering wraps this in
        // takes a comparable, and an Object-typed subquery is not one.
        final Class<?> valueClass = castedAttributeContentData.contains(contentType)
                ? contentType.getContentDataClass()
                : String.class;
        final Subquery subquery = query.subquery(valueClass);
        final Root<AttributeContent2Object> subqueryRoot = subquery.from(AttributeContent2Object.class);
        final Join joinContentItem = subqueryRoot.join(AttributeContent2Object_.attributeContentItem, JoinType.INNER);
        final Join joinDefinition = joinContentItem.join(AttributeContentItem_.attributeDefinition, JoinType.INNER);

        final Expression<String> extracted = criteriaBuilder
                .function(JSONB_EXTRACT_PATH_TEXT_FUNCTION_NAME, String.class,
                        joinContentItem.get(AttributeContentItem_.json),
                        criteriaBuilder.literal(contentType.isFilterByData() ? "data" : "reference"));
        final Expression<?> value = castedAttributeContentData.contains(contentType)
                ? ((JpaExpression<String>) extracted).cast(contentType.getContentDataClass())
                : extracted;

        final List<Predicate> predicates = new ArrayList<>(attributeCorrelationPredicates(criteriaBuilder, root,
                subqueryRoot, joinDefinition, attributeType, contentType, attributeName, resource, objectUuidPath));
        predicates
                .addAll(attributeReadabilityPredicates(criteriaBuilder, joinContentItem, joinDefinition, attributeType,
                        contentFilterSource, true));

        subquery.select(value).where(predicates.toArray(new Predicate[]{}));
        ((JpaSubQuery) subquery)
                .orderBy(criteriaBuilder.asc(joinContentItem.get(AttributeContentItem_.attributeDefinitionUuid)),
                        criteriaBuilder.asc(subqueryRoot.get(AttributeContent2Object_.order)))
                .fetch(1);

        return subquery;
    }

    /**
     * Refuses a value filter on content the projection withholds, which the catalogue offers presence conditions for
     * and nothing else. A presence filter reads no value, so it is answered.
     */
    private static void requireFilterableContentType(final String fieldIdentifier,
            final AttributeContentType contentType, final boolean readsStoredValue) {
        if (readsStoredValue && AttributeColumnProjector.WITHHELD_CONTENT_TYPES.contains(contentType)) {
            throw new ValidationException(ValidationError
                    .create("Field %s can only be filtered on whether a value is present.".formatted(fieldIdentifier)));
        }
    }

    /**
     * Whether the definition behind a content row says its attribute may be shown to a user. Reads the mirrored column,
     * so this cannot fall open on a document whose shape has moved.
     */
    private static Predicate definitionIsVisible(final CriteriaBuilder criteriaBuilder, final Join joinDefinition) {
        return criteriaBuilder.isTrue(joinDefinition.get(AttributeDefinition_.visible));
    }

    /**
     * The predicates that keep a query from reading content the same response would withhold: ciphertext, a disabled or
     * hidden custom definition, and definitions the caller's attribute permissions exclude.
     *
     * @param readsStoredValue whether the query reads the stored value rather than only asking whether one exists.
     * Encrypted content is offered presence conditions and nothing else, so excluding ciphertext rows from a presence
     * question would answer "no value" for content that is set.
     */
    private static List<Predicate> attributeReadabilityPredicates(final CriteriaBuilder criteriaBuilder,
            final Join joinContentItem, final Join joinDefinition, final AttributeType attributeType,
            final Supplier<CustomAttributeContentFilter> contentFilterSource, final boolean readsStoredValue) {
        final List<Predicate> predicates = new ArrayList<>();
        if (readsStoredValue) {
            predicates.add(criteriaBuilder.isNull(joinContentItem.get(AttributeContentItem_.encryptedData)));
        }
        // Only custom definitions carry a permission model and a visibility the platform enforces. On a data or
        // metadata definition `visible` is a connector's display hint, and the nullable `enabled` column is unset,
        // so applying either would drop rows a listing is meant to return.
        //
        // The projection and the catalogue do withhold a hidden data or metadata field, because those decide what is
        // rendered and a display hint governs that. Filtering is not rendering, so such a value stays answerable here
        // by design: the split is deliberate, not an oversight the projection predicate was meant to close.
        if (attributeType != AttributeType.CUSTOM) {
            return predicates;
        }
        predicates.add(definitionIsVisible(criteriaBuilder, joinDefinition));
        final CustomAttributeContentFilter contentFilter = contentFilterSource.get();

        predicates.add(criteriaBuilder.isTrue(joinDefinition.get(AttributeDefinition_.enabled)));
        final Path<UUID> definitionUuid = joinContentItem.get(AttributeContentItem_.attributeDefinitionUuid);
        if (contentFilter.allowedDefinitionUuids() != null) {
            predicates.add(definitionUuid.in(contentFilter.allowedDefinitionUuids()));
        }
        if (contentFilter.forbiddenDefinitionUuids() != null) {
            predicates.add(criteriaBuilder.not(definitionUuid.in(contentFilter.forbiddenDefinitionUuids())));
        }
        return predicates;
    }
}
