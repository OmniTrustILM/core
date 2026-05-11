package com.czertainly.core.util;

import com.czertainly.api.exception.ValidationException;
import com.czertainly.api.model.client.certificate.SearchFilterRequestDto;
import com.czertainly.api.model.common.attribute.common.AttributeType;
import com.czertainly.api.model.common.attribute.common.content.AttributeContentType;
import com.czertainly.api.model.common.enums.BitMaskEnum;
import com.czertainly.api.model.common.enums.IPlatformEnum;
import com.czertainly.api.model.core.auth.Resource;
import com.czertainly.api.model.core.search.FilterConditionOperator;
import com.czertainly.api.model.core.search.FilterFieldSource;
import com.czertainly.core.dao.entity.*;
import com.czertainly.core.enums.FilterField;
import com.czertainly.core.enums.ResourceToClass;
import com.czertainly.core.enums.SearchFieldTypeEnum;
import jakarta.persistence.EntityManager;
import jakarta.persistence.Query;
import jakarta.persistence.criteria.*;
import jakarta.persistence.metamodel.Attribute;
import jakarta.persistence.metamodel.PluralAttribute;
import org.hibernate.query.criteria.JpaExpression;

import javax.xml.datatype.DatatypeConfigurationException;
import javax.xml.datatype.DatatypeFactory;
import javax.xml.datatype.Duration;
import java.io.Serializable;
import java.time.*;
import java.time.format.DateTimeFormatter;
import java.util.*;
import java.util.regex.Pattern;
import java.util.regex.PatternSyntaxException;
import java.util.stream.Collectors;

public class FilterPredicatesBuilder {

    public static final String EMPTY_JSON_ARRAY = "[]";
    public static final String NULL_JSON_ARRAY = "[null]";

    private FilterPredicatesBuilder() {
        throw new IllegalStateException("Static utility class");
    }

    private static final List<AttributeContentType> castedAttributeContentData = List.of(AttributeContentType.INTEGER, AttributeContentType.FLOAT, AttributeContentType.DATE, AttributeContentType.TIME, AttributeContentType.DATETIME);
    private static final String JSONB_EXTRACT_PATH_TEXT_FUNCTION_NAME = "jsonb_extract_path_text";
    private static final String TEXTREGEXEQ_FUNCTION_NAME = "textregexeq";
    private static final String ARRAY_CONTAINS_FUNCTION_NAME = PostgresFunctionContributor.ARRAY_CONTAINS;

    public static <T> Predicate getFiltersPredicate(final CriteriaBuilder criteriaBuilder, final CommonAbstractCriteria query, final Root<T> root, final List<SearchFilterRequestDto> filterDtos) {
        Map<String, From> joinedAssociations = new HashMap<>();

        List<Predicate> predicates = new ArrayList<>();
        if (filterDtos != null) {
            for (SearchFilterRequestDto filterDto : filterDtos) {
                if (filterDto.getFieldSource() == FilterFieldSource.PROPERTY) {
                    predicates.add(getPropertyFilterPredicate(criteriaBuilder, query, root, filterDto, joinedAssociations));
                } else {
                    predicates.add(getAttributeFilterPredicate(criteriaBuilder, query, root, filterDto));
                }
            }
        }

        return criteriaBuilder.and(predicates.toArray(new Predicate[]{}));
    }

    private static <T> Predicate getAttributeFilterPredicate(final CriteriaBuilder criteriaBuilder, final CommonAbstractCriteria query, final Root<T> root, final SearchFilterRequestDto filterDto) {
        final Subquery<Integer> subquery = query.subquery(Integer.class);
        final Root<AttributeContent2Object> subqueryRoot = subquery.from(AttributeContent2Object.class);
        final Join joinContentItem = subqueryRoot.join(AttributeContent2Object_.attributeContentItem, JoinType.INNER);
        final Join joinDefinition = joinContentItem.join(AttributeContentItem_.attributeDefinition, JoinType.INNER);

        final AttributeType attributeType = filterDto.getFieldSource().getAttributeType();
        final String identifier = filterDto.getFieldIdentifier();
        final String[] fieldIdentifier = identifier.split("\\|");
        final AttributeContentType contentType = AttributeContentType.valueOf(fieldIdentifier[1]);
        final String attributeName = fieldIdentifier[0];
        final boolean isNotExistCondition = List.of(FilterConditionOperator.NOT_EQUALS, FilterConditionOperator.NOT_CONTAINS, FilterConditionOperator.EMPTY, FilterConditionOperator.NOT_MATCHES).contains(filterDto.getCondition());

        // attributes content for cryptographic key items are stored under resource CRYPTOGRAPHIC_KEY, but for meta attributes, object uuid is uuid of cryptographic key item and for custom and data attribute it is uuid of cryptographic key
        // place for improvement is to consolidate resource for attributes content
        final Resource resource = root.getJavaType().equals(CryptographicKeyItem.class) ? Resource.CRYPTOGRAPHIC_KEY : ResourceToClass.getResourceByClass(root.getJavaType());
        final String objectUuidPath = resource == Resource.CRYPTOGRAPHIC_KEY && (attributeType == AttributeType.CUSTOM || attributeType == AttributeType.DATA) ? CryptographicKeyItem_.keyUuid.getName() : UniquelyIdentified_.uuid.getName();

        List<Predicate> predicates = new ArrayList<>();
        predicates.add(criteriaBuilder.equal(joinDefinition.get(AttributeDefinition_.type), attributeType));
        predicates.add(criteriaBuilder.equal(joinDefinition.get(AttributeDefinition_.contentType), contentType));
        predicates.add(criteriaBuilder.equal(joinDefinition.get(AttributeDefinition_.name), attributeName));
        predicates.add(criteriaBuilder.equal(subqueryRoot.get(AttributeContent2Object_.objectType), resource));
        predicates.add(criteriaBuilder.equal(subqueryRoot.get(AttributeContent2Object_.objectUuid), root.get(objectUuidPath)));


        if (filterDto.getCondition() != FilterConditionOperator.EMPTY && filterDto.getCondition() != FilterConditionOperator.NOT_EMPTY) {
            Expression<String> attributeContentExpression = criteriaBuilder.function(JSONB_EXTRACT_PATH_TEXT_FUNCTION_NAME, String.class, joinContentItem.get(AttributeContentItem_.json), criteriaBuilder.literal(contentType.isFilterByData() ? "data" : "reference"));
            CriteriaBuilder.SimpleCase<AttributeContentType, Object> contentTypeCaseExpression = criteriaBuilder.selectCase(joinDefinition.get(AttributeDefinition_.contentType));

            if (castedAttributeContentData.contains(contentType)) {
                contentTypeCaseExpression.when(contentType, ((JpaExpression) attributeContentExpression).cast(contentType.getContentDataClass())).otherwise(criteriaBuilder.nullLiteral(contentType.getContentDataClass()));
            } else {
                contentTypeCaseExpression.when(contentType, attributeContentExpression).otherwise(criteriaBuilder.nullLiteral(String.class));
            }

            Predicate conditionPredicate = getAttributeFilterConditionPredicate(criteriaBuilder, filterDto, contentTypeCaseExpression, contentType);
            predicates.add(conditionPredicate);
        }

        subquery.select(criteriaBuilder.literal(1)).where(predicates.toArray(new Predicate[]{}));
        return isNotExistCondition ? criteriaBuilder.not(criteriaBuilder.exists(subquery)) : criteriaBuilder.exists(subquery);
    }

    private static Predicate getAttributeFilterConditionPredicate(final CriteriaBuilder criteriaBuilder, final SearchFilterRequestDto filterDto, final Expression expression, final AttributeContentType contentType) {
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
                yield criteriaBuilder.between(expression,
                        nowDateTime.minus(Period.of(duration.getYears(), duration.getMonths(), duration.getDays())).minusHours(duration.getHours()).minusMinutes(duration.getMinutes()).minusSeconds(duration.getSeconds()),
                        nowDateTime);
            }
            case IN_NEXT -> {
                Duration duration = (Duration) filterValues.getFirst();
                yield criteriaBuilder.between(expression, nowDateTime,
                        nowDateTime.plus(Period.of(duration.getYears(), duration.getMonths(), duration.getDays())).plusHours(duration.getHours()).plusMinutes(duration.getMinutes()).plusSeconds(duration.getSeconds()));
            }
            case MATCHES -> {
                validateRegexForDbQuery(filterValues.getFirst().toString());
                yield criteriaBuilder.equal(criteriaBuilder.function(TEXTREGEXEQ_FUNCTION_NAME, Boolean.class, expression, criteriaBuilder.literal(filterValues.getFirst())), true);
            }
            case null, default -> null;
        };
    }

    private static List<Object> prepareAttributeFilterValues(final SearchFilterRequestDto filterDto, final AttributeContentType contentType) {
        Serializable filterValue = filterDto.getValue();

        if (filterValue == null) {
            return List.of();
        }

        final List<Object> preparedFilterValues = new ArrayList<>();
        List<Object> filterValues = filterValue instanceof List<?> ? (List<Object>) filterValue : List.of(filterValue);
        for (Object value : filterValues) {
            String stringValue = value.toString();
            Object preparedValue;
            if (filterDto.getCondition() == FilterConditionOperator.IN_NEXT || filterDto.getCondition() == FilterConditionOperator.IN_PAST) {
                preparedValue = prepareDurationValue(contentType, stringValue);
            } else {
                preparedValue = switch (contentType) {
                    case BOOLEAN -> Boolean.parseBoolean(stringValue) ? "true" : "false";
                    case INTEGER -> {
                        try {
                            yield Integer.parseInt(stringValue);
                        } catch (NumberFormatException e) {
                            throw new ValidationException("Filter field value " + stringValue + " cannot be parsed as an Integer.");
                        }
                    }
                    case FLOAT -> {
                        try {
                            yield Float.parseFloat(stringValue);
                        } catch (NumberFormatException e) {
                            throw new ValidationException("Filter field value " + stringValue + " cannot be parsed as a Float.");
                        }
                    }
                    case DATE -> LocalDate.parse(stringValue);
                    case TIME -> LocalTime.parse(stringValue);
                    case DATETIME -> {
                        if (!stringValue.contains("+") && !stringValue.endsWith("Z")) {
                            stringValue += "Z";
                        }
                        yield ZonedDateTime.parse(stringValue, DateTimeFormatter.ofPattern("[yyyy-MM-dd'T'HH:mm:ss.SSSXXX][yyyy-MM-dd'T'HH:mm:ssXXX][yyyy-MM-dd'T'HH:mmXXX]"));
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

    private static <T> Predicate getPropertyFilterPredicate(final CriteriaBuilder criteriaBuilder, final CommonAbstractCriteria query, final Root<T> root, SearchFilterRequestDto filterDto, Map<String, From> joinedAssociations) {
        final FilterField filterField = FilterField.valueOf(filterDto.getFieldIdentifier());
        From from = getJoinedAssociation(root, joinedAssociations, filterField, filterDto.getCondition());

        // prepare filter values, expression and set filter characteristics
        List<Object> filterValues = preparePropertyFilterValues(filterDto, filterField);
        if (filterValues.isEmpty()
                && filterDto.getCondition() != FilterConditionOperator.EMPTY
                && filterDto.getCondition() != FilterConditionOperator.NOT_EMPTY) {
            throw new ValidationException("Filter for field " + filterField + " with operator " + filterDto.getCondition() + " requires at least one value.");
        }

        Expression expression = null;
        if (filterField.getFieldAttribute() != null && !isCountOperator(filterDto.getCondition()))
            expression = from.get(filterField.getFieldAttribute().getName());

        boolean isJsonArray = false;
        if (filterField.getJsonPath() != null) {
            isJsonArray = isJsonArray(filterField);
            if (isJsonArray) {
                expression = criteriaBuilder.function("jsonb_path_query_array",
                        String.class,
                        from.get(filterField.getFieldAttribute().getName()),
                        criteriaBuilder.literal(getArrayJsonPath(filterField.getJsonPath())));
            } else {
                expression = switch (filterField.getJsonPath().length) {
                    case 1 ->
                            criteriaBuilder.function(JSONB_EXTRACT_PATH_TEXT_FUNCTION_NAME, String.class, from.get(filterField.getFieldAttribute().getName()), criteriaBuilder.literal(filterField.getJsonPath()[0]));
                    case 2 ->
                            criteriaBuilder.function(JSONB_EXTRACT_PATH_TEXT_FUNCTION_NAME, String.class, from.get(filterField.getFieldAttribute().getName()), criteriaBuilder.literal(filterField.getJsonPath()[0]), criteriaBuilder.literal(filterField.getJsonPath()[1]));
                    case 3 ->
                            criteriaBuilder.function(JSONB_EXTRACT_PATH_TEXT_FUNCTION_NAME, String.class, from.get(filterField.getFieldAttribute().getName()), criteriaBuilder.literal(filterField.getJsonPath()[0]), criteriaBuilder.literal(filterField.getJsonPath()[1]), criteriaBuilder.literal(filterField.getJsonPath()[2]));
                    case 4 ->
                            criteriaBuilder.function(JSONB_EXTRACT_PATH_TEXT_FUNCTION_NAME, String.class, from.get(filterField.getFieldAttribute().getName()), criteriaBuilder.literal(filterField.getJsonPath()[0]), criteriaBuilder.literal(filterField.getJsonPath()[1]), criteriaBuilder.literal(filterField.getJsonPath()[2]), criteriaBuilder.literal(filterField.getJsonPath()[3]));
                    default ->
                            throw new ValidationException("Unexpected size of JSON path `%s`: %d".formatted(Arrays.toString(filterField.getJsonPath()), filterField.getJsonPath().length));
                };
            }
        } else if (filterField.getType().getExpressionClass() != null && filterField.getExpectedValue() == null) {
            if (expression == null)
                throw new ValidationException("Invalid filter configuration: no expression for field " + filterField);
            expression = ((JpaExpression) expression).cast(filterField.getType().getExpressionClass());
        }

        boolean multipleValues = filterValues.size() > 1;
        boolean hasParent = !filterField.getJoinAttributes().isEmpty() && filterField.getFieldResource() != Resource.USER; // workaround for owner => fieldResource = USER
        boolean isParentCollection = hasParent && filterField.getJoinAttributes().getLast().isCollection();
        PluralAttribute.CollectionType parentCollectionType = hasParent && isParentCollection ? ((PluralAttribute) filterField.getJoinAttributes().getLast()).getCollectionType() : null;

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
        boolean bitEnumProperty = filterField.getEnumClass() != null && BitMaskEnum.class.isAssignableFrom(filterField.getEnumClass());
        boolean isNativeArrayField = filterField.getType() == SearchFieldTypeEnum.NATIVE_ARRAY;
        if (expression == null && !isCountOperator(conditionOperator))
            throw new ValidationException("Invalid filter configuration: no expression for field " + filterField + " with operator " + conditionOperator);
        final Expression finalExpression = expression;
        switch (conditionOperator) {
            case EQUALS -> {
                if (bitEnumProperty)
                    predicate = criteriaBuilder.notEqual(getBitwiseEqualExpression(filterValues.getFirst(), expression, criteriaBuilder), 0);
                else if (isJsonArray)
                    predicate = criteriaBuilder.isTrue(getJsonArrayEqualsExpression(criteriaBuilder, expression, filterValues.getFirst().toString()));
                else if (isNativeArrayField) {
                    List<Predicate> nativeArrayPredicates = filterValues.stream()
                            .map(value -> criteriaBuilder.isTrue(criteriaBuilder.function(
                                    ARRAY_CONTAINS_FUNCTION_NAME,
                                    Boolean.class,
                                    criteriaBuilder.literal(value.toString()),
                                    finalExpression
                            )))
                            .toList();
                    predicate = nativeArrayPredicates.size() == 1
                            ? nativeArrayPredicates.getFirst()
                            : criteriaBuilder.or(nativeArrayPredicates.toArray(new Predicate[0]));
                } else
                    predicate = multipleValues ? expression.in(filterValues) : criteriaBuilder.equal(expression, filterValues.getFirst());
            }
            case NOT_EQUALS -> {
                if (bitEnumProperty)
                    predicate = criteriaBuilder.equal(getBitwiseEqualExpression(filterValues.getFirst(), expression, criteriaBuilder), 0);
                else if (isJsonArray)
                    predicate = criteriaBuilder.isFalse(getJsonArrayEqualsExpression(criteriaBuilder, expression, filterValues.getFirst().toString()));
                else if (isNativeArrayField) {
                    Predicate[] nativeArrayNotContainsPredicates = filterValues.stream()
                            .map(value -> criteriaBuilder.isFalse(criteriaBuilder.function(
                                    ARRAY_CONTAINS_FUNCTION_NAME,
                                    Boolean.class,
                                    criteriaBuilder.literal(value.toString()),
                                    finalExpression
                            )))
                            .toArray(Predicate[]::new);
                    predicate = criteriaBuilder.or(
                            criteriaBuilder.isNull(expression),
                            criteriaBuilder.and(nativeArrayNotContainsPredicates)
                    );
                }
                else {
                    // hack how to filter out correctly Has private key property filter for certificate. Needs to find correct solution for SET attributes predicates!
                    if (filterField.getExpectedValue() != null && filterField == FilterField.PRIVATE_KEY) {
                        predicate = criteriaBuilder.or(criteriaBuilder.and(criteriaBuilder.notEqual(expression, filterValues.getFirst()), criteriaBuilder.equal(expression, filterValues.getFirst())), criteriaBuilder.isNull(expression));
                    } else {
                        predicate = filterField.getFieldResource() == Resource.GROUP
                                ? getGroupNotExistPredicate(criteriaBuilder, query, root, filterField.getFieldAttribute(), filterValues, filterField.getRootResource())
                                : criteriaBuilder.or(getNotPresentPredicate(criteriaBuilder, from, expression, hasParent, isParentCollection, false, isJsonArray), multipleValues ? criteriaBuilder.not(expression.in(filterValues)) : criteriaBuilder.notEqual(expression, filterValues.getFirst()));
                    }
                }
            }
            case STARTS_WITH -> predicate = criteriaBuilder.like(expression, filterValues.getFirst() + "%");
            case ENDS_WITH -> predicate = criteriaBuilder.like(expression, "%" + filterValues.getFirst());
            case CONTAINS -> predicate = criteriaBuilder.like(expression, "%" + filterValues.getFirst() + "%");
            case NOT_CONTAINS ->
                    predicate = criteriaBuilder.or(getNotPresentPredicate(criteriaBuilder, from, expression, hasParent, isParentCollection, false, isJsonArray),
                            criteriaBuilder.notLike(expression, "%" + filterValues.getFirst() + "%"));
            case EMPTY -> {
                if (isNativeArrayField)
                    predicate = criteriaBuilder.or(criteriaBuilder.isNull(expression),
                            criteriaBuilder.equal(criteriaBuilder.function("cardinality", Integer.class, expression), 0));
                else
                    predicate = getNotPresentPredicate(criteriaBuilder, from, expression, hasParent, isParentCollection, bitEnumProperty, isJsonArray);
            }
            case NOT_EMPTY -> {
                if (isNativeArrayField)
                    predicate = criteriaBuilder.and(criteriaBuilder.isNotNull(expression),
                            criteriaBuilder.greaterThan(criteriaBuilder.function("cardinality", Integer.class, expression), 0));
                else
                    predicate = criteriaBuilder.not(getNotPresentPredicate(criteriaBuilder, from, expression, hasParent, isParentCollection, bitEnumProperty, isJsonArray));
            }
            case GREATER ->
                    predicate = criteriaBuilder.greaterThan(expression, (Expression) criteriaBuilder.literal(filterValues.getFirst()));
            case GREATER_OR_EQUAL ->
                    predicate = criteriaBuilder.greaterThanOrEqualTo(expression, (Expression) criteriaBuilder.literal(filterValues.getFirst()));
            case LESSER ->
                    predicate = criteriaBuilder.lessThan(expression, (Expression) criteriaBuilder.literal(filterValues.getFirst()));
            case LESSER_OR_EQUAL ->
                    predicate = criteriaBuilder.lessThanOrEqualTo(expression, (Expression) criteriaBuilder.literal(filterValues.getFirst()));
            case IN_PAST -> {
                Duration duration = (Duration) filterValues.getFirst();
                predicate = criteriaBuilder.between(expression,
                        now.minus(Period.of(duration.getYears(), duration.getMonths(), duration.getDays())).minusHours(duration.getHours()).minusMinutes(duration.getMinutes()).minusSeconds(duration.getSeconds()),
                        now);
            }
            case IN_NEXT -> {
                Duration duration = (Duration) filterValues.getFirst();
                predicate = criteriaBuilder.between(expression, now,
                        now.plus(Period.of(duration.getYears(), duration.getMonths(), duration.getDays())).plusHours(duration.getHours()).plusMinutes(duration.getMinutes()).plusSeconds(duration.getSeconds()));
            }
            case MATCHES -> {
                validateRegexForDbQuery(filterValues.getFirst().toString());
                predicate = criteriaBuilder.equal(criteriaBuilder.function(TEXTREGEXEQ_FUNCTION_NAME, Boolean.class, expression, criteriaBuilder.literal(filterValues.getFirst())), true);
            }
            case NOT_MATCHES -> {
                validateRegexForDbQuery(filterValues.getFirst().toString());
                predicate = criteriaBuilder.equal(criteriaBuilder.function(TEXTREGEXEQ_FUNCTION_NAME, Boolean.class, expression, criteriaBuilder.literal(filterValues.getFirst())), false);
            }
            case COUNT_EQUAL -> predicate = criteriaBuilder.equal(criteriaBuilder.size(from), filterValues.getFirst());
            case COUNT_NOT_EQUAL ->
                    predicate = criteriaBuilder.not(criteriaBuilder.equal(criteriaBuilder.size(from), filterValues.getFirst()));
            case COUNT_GREATER_THAN -> {
                try {
                    predicate = criteriaBuilder.greaterThan(criteriaBuilder.size(from), (Expression) criteriaBuilder.literal(Integer.parseInt(filterValues.getFirst().toString())));
                } catch (NumberFormatException e) {
                    throw new ValidationException("Filter field value " + filterValues.getFirst() + " cannot be parsed as an Integer.");
                }
            }
            case COUNT_LESS_THAN -> {
                try {
                    predicate = criteriaBuilder.lessThan(criteriaBuilder.size(from), (Expression) criteriaBuilder.literal(Integer.parseInt(filterValues.getFirst().toString())));
                } catch (NumberFormatException e) {
                    throw new ValidationException("Filter field value " + filterValues.getFirst() + " cannot be parsed as an Integer.");
                }
            }

            default -> throw new ValidationException("Unexpected value: " + conditionOperator);
        }
        return predicate;
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

    private static Expression<Boolean> getJsonArrayEqualsExpression(CriteriaBuilder criteriaBuilder, Expression expression, String filterValue) {
        return criteriaBuilder.function(
                PostgresFunctionContributor.JSONB_CONTAINS,
                Boolean.class,
                expression,
                criteriaBuilder.literal(
                        "[\"%s\"]".formatted(filterValue)
                )
        );
    }

    private static Expression<?> getBitwiseEqualExpression(Object bit, Expression expression, CriteriaBuilder criteriaBuilder) {
        return criteriaBuilder.function(PostgresFunctionContributor.BIT_AND_FUNCTION, Integer.class, expression, criteriaBuilder.literal(bit));
    }

    private static void validateRegexForDbQuery(String regex) {
        try {
            Pattern.compile(regex);
        } catch (PatternSyntaxException e) {
            throw new ValidationException("Input is not a valid regex: " + e.getMessage());
        }

        // Literals \Q, \R, \G, ... are forbidden, but \\Q, \\R, \\G, ... should stay allowed
        if (containsUnescapedSlashFollowedBy(regex, "QRGhHzXV")) {
            throw new ValidationException("Literal quote sequences \\Q, \\R, \\G, \\h, \\H, \\z, \\X, \\V are not supported in PostgreSQL POSIX regex");
        }
    }

    private static boolean containsUnescapedSlashFollowedBy(String s, String chars) {
        for (int i = 0; i < s.length() - 1; i++) {
            if (s.charAt(i) != '\\') continue;
            char next = s.charAt(i + 1);
            if (chars.indexOf(next) < 0) continue;
            // count backslashes immediately before s.charAt(i)
            int j = i - 1;
            int count = 0;
            while (j >= 0 && s.charAt(j) == '\\') { count++; j--; }
            // if count is even -> this backslash is not escaped
            if ((count % 2) == 0) return true;
        }
        return false;
    }


    private static <T> From getJoinedAssociation(Root<T> root, Map<String, From> joinedAssociations, FilterField filterField, FilterConditionOperator condition) {
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
        return condition == FilterConditionOperator.COUNT_EQUAL || condition == FilterConditionOperator.COUNT_NOT_EQUAL || condition == FilterConditionOperator.COUNT_GREATER_THAN || condition == FilterConditionOperator.COUNT_LESS_THAN;
    }

    private static List<Object> preparePropertyFilterValues(final SearchFilterRequestDto filterDto, final FilterField filterField) {
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
                    final BitMaskEnum enumValue = (BitMaskEnum) findEnumByCustomValue(value, filterField.getEnumClass());
                    if (enumValue != null) {
                        preparedFilterValue = enumValue.getBit();
                    }
                } else {
                    preparedFilterValue = findEnumByCustomValue(value, filterField.getEnumClass());
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
                        preparedFilterValue = stringValue.contains(".") ? Float.parseFloat(stringValue) : Integer.parseInt(stringValue);
                    } catch (NumberFormatException e) {
                        throw new ValidationException("Filter field value " + stringValue + " cannot be parsed as a Number.");
                    }
                } else if (filterDto.getCondition() == FilterConditionOperator.IN_PAST || filterDto.getCondition() == FilterConditionOperator.IN_NEXT) {
                    try {
                        if (filterField.getType() == SearchFieldTypeEnum.DATE) {
                            stringValue = extractDateFromDuration(stringValue);
                        }
                        preparedFilterValue = DatatypeFactory.newInstance().newDuration(stringValue);
                    } catch (Exception e) {
                        throw new ValidationException("Filter field value " + stringValue + " cannot be parsed to a Duration.");
                    }
                } else if (filterField.getType() == SearchFieldTypeEnum.DATE) {
                    preparedFilterValue = LocalDate.parse(stringValue);
                } else if (filterField.getType() == SearchFieldTypeEnum.DATETIME) {
                    preparedFilterValue = LocalDateTime.parse(stringValue, DateTimeFormatter.ofPattern("[yyyy-MM-dd'T'HH:mm:ss.SSSXXX][yyyy-MM-dd'T'HH:mm:ssXXX][yyyy-MM-dd'T'HH:mmXXX]"));
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

    private static Predicate getGroupNotExistPredicate(final CriteriaBuilder criteriaBuilder, final CommonAbstractCriteria query, Root originalRoot, Attribute fieldAttribute, List<Object> filterValues, Resource resource) {
        final Subquery<Integer> subquery = query.subquery(Integer.class);
        final Root<GroupAssociation> subqueryRoot = subquery.from(GroupAssociation.class);
        final Join joinGroup = subqueryRoot.join(GroupAssociation_.group);
        subquery.select(criteriaBuilder.literal(1)).where(
                criteriaBuilder.equal(subqueryRoot.get(ResourceObjectAssociation_.resource), resource),
                criteriaBuilder.equal(subqueryRoot.get(ResourceObjectAssociation_.objectUuid), resource == Resource.CRYPTOGRAPHIC_KEY ? originalRoot.get(CryptographicKeyItem_.keyUuid) : originalRoot.get(UniquelyIdentified_.uuid)),
                joinGroup.get(fieldAttribute.getName()).in(filterValues));

        return criteriaBuilder.not(criteriaBuilder.exists(subquery));
    }

    private static Predicate getNotPresentPredicate(final CriteriaBuilder criteriaBuilder, From from, Expression expression, boolean hasParent, boolean isParentCollection, boolean isEnumList, boolean isJsonArray) {
        if (isEnumList) {
            return criteriaBuilder.equal(expression, 0);
        }

        if (isJsonArray) {
            return criteriaBuilder.or(criteriaBuilder.equal(expression, criteriaBuilder.literal(EMPTY_JSON_ARRAY)), criteriaBuilder.isNull(expression), criteriaBuilder.equal(expression, criteriaBuilder.literal(NULL_JSON_ARRAY)));
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
        Optional<? extends IPlatformEnum> enumItem = Arrays.stream(enumClass.getEnumConstants()).filter(enumValue -> enumValue.getCode().equals(valueObject.toString())).findFirst();
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

    public static Predicate constructFilterForJobHistory(final CriteriaBuilder cb, final Root<ScheduledJobHistory> root, final UUID scheduledJobUuid) {
        final Expression<?> expressionPath = prepareExpression(root, "scheduledJobUuid");
        return cb.equal(expressionPath, scheduledJobUuid);
    }

    public static String buildPathToProperty(List<Attribute> joinAttributes, Attribute fieldAttribute) {
        StringBuilder pathToPropertyBuilder = new StringBuilder();

        if (joinAttributes != null && !joinAttributes.isEmpty()) {
            // join attribute names with a dot
            pathToPropertyBuilder.append(
                    joinAttributes.stream()
                            .map(Attribute::getName)
                            .collect(Collectors.joining("."))
            );
        }

        if (fieldAttribute != null) {
            if (!pathToPropertyBuilder.isEmpty()) {
                pathToPropertyBuilder.append(".");
            }
            pathToPropertyBuilder.append(fieldAttribute.getName());
        }
        return pathToPropertyBuilder.toString();
    }
}
