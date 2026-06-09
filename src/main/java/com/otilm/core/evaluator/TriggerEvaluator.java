package com.otilm.core.evaluator;

import com.otilm.api.exception.*;
import com.otilm.api.model.client.attribute.ResponseAttribute;
import com.otilm.api.model.client.attribute.ResponseAttributeV3;
import com.otilm.api.model.client.metadata.MetadataResponseDto;
import com.otilm.api.model.client.metadata.ResponseMetadata;
import com.otilm.api.model.common.attribute.common.AttributeContent;
import com.otilm.api.model.common.attribute.common.content.AttributeContentType;
import com.otilm.api.model.common.attribute.v3.content.BaseAttributeContentV3;
import com.otilm.api.model.common.enums.IPlatformEnum;
import com.otilm.api.model.common.events.data.CertificateEventData;
import com.otilm.api.model.core.auth.Resource;
import com.otilm.api.model.core.other.ResourceEvent;
import com.otilm.api.model.core.search.FilterConditionOperator;
import com.otilm.api.model.core.search.FilterFieldSource;
import com.otilm.api.model.core.search.FilterFieldType;
import com.otilm.api.model.core.workflows.ExecutionType;
import com.otilm.core.attribute.engine.AttributeEngine;
import com.otilm.core.attribute.engine.AttributeVersionHelper;
import com.otilm.core.attribute.engine.records.ObjectAttributeContentInfo;
import com.otilm.core.dao.entity.ComplianceInternalRule;
import com.otilm.core.dao.entity.UniquelyIdentifiedObject;
import com.czertainly.core.dao.entity.workflows.*;
import com.otilm.core.dao.entity.workflows.*;
import com.otilm.core.enums.FilterField;
import com.otilm.core.enums.ResourceToClass;
import com.otilm.core.messaging.model.NotificationMessage;
import com.otilm.core.service.TriggerInternalService;
import com.otilm.core.util.AttributeDefinitionUtils;
import com.otilm.core.util.FilterPredicatesBuilder;
import jakarta.persistence.metamodel.Attribute;
import org.apache.commons.beanutils.PropertyUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Transactional;

import javax.xml.datatype.DatatypeFactory;
import javax.xml.datatype.Duration;
import java.lang.reflect.InvocationTargetException;
import java.time.LocalDate;
import java.time.LocalDateTime;
import java.time.Period;
import java.time.ZoneId;
import java.time.format.DateTimeFormatter;
import java.util.*;
import java.util.function.BiFunction;

@Component
@Transactional
public class TriggerEvaluator<T extends UniquelyIdentifiedObject> implements ITriggerEvaluator<T> {

    protected static final Logger logger = LoggerFactory.getLogger(TriggerEvaluator.class);
    private static final String DATETIME_FORMAT = "yyyy-MM-dd'T'HH:mm:ss.SSSXXX";

    private AttributeEngine attributeEngine;

    private TriggerInternalService triggerService;
    private ApplicationEventPublisher applicationEventPublisher;

    @Autowired
    public void setApplicationEventPublisher(ApplicationEventPublisher applicationEventPublisher) {
        this.applicationEventPublisher = applicationEventPublisher;
    }

    @Autowired
    public void setTriggerService(TriggerInternalService triggerService) {
        this.triggerService = triggerService;
    }

    @Autowired
    public void setAttributeEngine(AttributeEngine attributeEngine) {
        this.attributeEngine = attributeEngine;
    }

    @Override
    public TriggerHistory evaluateTrigger(Trigger trigger, TriggerAssociation triggerAssociation, T object, UUID referenceObjectUuid, Object data, EventHistory eventHistory) throws RuleException {
        TriggerHistory triggerHistory = triggerService.createTriggerHistory(trigger.getUuid(), triggerAssociation, object.getUuid(), referenceObjectUuid, eventHistory, trigger.getResource());
        if (evaluateRules(triggerHistory, trigger.getRules(), object)) {
            triggerHistory.setConditionsMatched(true);
            if (trigger.isIgnoreTrigger()) {
                if (data instanceof CertificateEventData) triggerHistory.setMessage(data.toString());
                triggerHistory.setActionsPerformed(true);
            } else {
                performActions(trigger, triggerHistory, object, data);
                triggerHistory.setActionsPerformed(triggerHistory.getRecords().isEmpty());
            }
        } else {
            triggerHistory.setConditionsMatched(false);
            triggerHistory.setActionsPerformed(false);
        }

        return triggerHistory;
    }

    @Override
    public boolean evaluateRules(TriggerHistory triggerHistory, Set<Rule> rules, T object) throws RuleException {
        // if trigger has no rules, return true as it is trigger that should perform actions on all objects
        if (rules.isEmpty()) {
            return true;
        }

        // Rule evaluated is check if any rule has been evaluated, no rules will be evaluated if all rules in the list have incompatible resource
        boolean ruleEvaluated = false;
        for (Rule rule : rules) {
            logger.debug("Evaluating rule '{}'.", rule.getName());
            // Check if resource in the rule corresponds to the class of evaluator

            Class resourceClass = ResourceToClass.getClassByResource(rule.getResource());
            if (resourceClass == null) {
                throw new RuleException("Unknown class for resource " + rule.getResource().getLabel());
            }

            if (!resourceClass.isInstance(object)) {
                logger.debug("Rule '{}' has been skipped due to incompatible resource.", rule.getName());
                continue;
            }
            ruleEvaluated = true;
            for (Condition condition : rule.getConditions()) {
                for (ConditionItem conditionItem : condition.getItems()) {
                    if (!getConditionEvaluationResult(conditionItem, object, triggerHistory, rule)) return false;
                }
            }
        }

        if (ruleEvaluated) {
            logger.debug("All rules in the list have been satisfied for the object.");
        } else {
            logger.debug("No rules from the list have been evaluated, rules are not satisfied for the object.");
        }
        return ruleEvaluated;
    }

    @Override
    public boolean evaluateInternalRule(ComplianceInternalRule internalRule, T object) throws RuleException {
        // if rule has no conditions, return true as it is rule that should be satisfied for all objects
        if (internalRule.getConditionItems().isEmpty()) {
            return true;
        }

        for (ConditionItem conditionItem : internalRule.getConditionItems()) {
            if (!evaluateConditionItem(conditionItem, object, internalRule.getResource())) {
                return false;
            }
        }

        return true;
    }

    @Override
    public boolean evaluateConditionItem(ConditionItem conditionItem, T object, Resource resource) throws RuleException {
        FilterFieldSource fieldSource = conditionItem.getFieldSource();
        String fieldIdentifier = conditionItem.getFieldIdentifier();
        FilterConditionOperator operator = conditionItem.getOperator();
        Object conditionValue = conditionItem.getValue();

        // First, check where from to get object value based on Field Source
        if (fieldSource == FilterFieldSource.PROPERTY) {
            return evaluatePropertyConditionItem(object, resource, fieldIdentifier, operator, conditionValue);
        }

        // Check for UUID in the object, if there is no UUID, it means that the object is not yet in database and therefore won't have any attributes linked to it
        UUID objectUuid;
        try {
            objectUuid = (UUID) PropertyUtils.getProperty(object, "uuid");
        } catch (IllegalAccessException | InvocationTargetException | NoSuchMethodException e) {
            throw new RuleException("Cannot get UUID from resource " + resource + ".");
        }

        if (objectUuid != null) {
            if (fieldSource == FilterFieldSource.CUSTOM) {
                return evaluateCustomAttributeConditionItem(resource, objectUuid, fieldIdentifier, conditionValue, operator);
            }

            if (fieldSource == FilterFieldSource.META) {
                return evaluateMetaAttributeConditionItem(resource, fieldIdentifier, objectUuid, conditionValue, operator);
            }
        }
        // Field source is not Property and object is not database, therefore attributes can not be evaluated and condition is not satisfied
        return false;
    }

    private boolean evaluatePropertyConditionItem(T object, Resource resource, String fieldIdentifier, FilterConditionOperator operator, Object conditionValue) throws RuleException {
        Object objectValue;
        FilterField filterField;
        try {
            filterField = Enum.valueOf(FilterField.class, fieldIdentifier);
        } catch (IllegalArgumentException e) {
            throw new RuleException("Field identifier '" + fieldIdentifier + "' is not supported.");
        }

        List<Attribute> nestedJoinAttributes = null;
        List<Attribute> nonNestedJoinAttributes = null;

        boolean isNested = filterField.getJoinAttributes() != null && !filterField.getJoinAttributes().isEmpty();
        if (isNested) {
            List<Attribute> joinAttributes = new ArrayList<>(filterField.getJoinAttributes());
            // Find index which separates path to object holding property to check against and path to the property in that object
            int lastCollectionAttributeIndex = FilterPredicatesBuilder.getLastCollectionIndex(
                    joinAttributes, joinAttributes.size()
            );
            // If the object is already nested, the path to the property in that object is needed
            nestedJoinAttributes = new ArrayList<>(joinAttributes.subList(lastCollectionAttributeIndex, joinAttributes.size()));
            // Otherwise the path to the nested object is needed
            nonNestedJoinAttributes = new ArrayList<>(joinAttributes.subList(0, lastCollectionAttributeIndex));
        }

        try {
            boolean anyCollection = nonNestedJoinAttributes != null && !nonNestedJoinAttributes.isEmpty() && nonNestedJoinAttributes.getLast().isCollection();
            Attribute fieldAttribute = isNested && anyCollection ? null : filterField.getFieldAttribute();
            objectValue = getPropertyValue(object, nonNestedJoinAttributes, fieldAttribute);
        } catch (IllegalAccessException | InvocationTargetException | NoSuchMethodException e) {
            throw new RuleException("Cannot get property " + fieldIdentifier + " from resource " + resource + ".");
        }

        FilterFieldType fieldType = filterField.getType().getFieldType();


        // Apply comparing function on value in object and value in condition, based on operator and field type, return whether the condition is satisfied
        try {
            if (!(objectValue instanceof Collection<?> objectValues)) {
                if (objectValue != null && filterField.getEnumClass() != null) {
                    objectValue = ((IPlatformEnum) objectValue).getCode();
                }
                return fieldTypeToOperatorActionMap.get(fieldType).get(operator).apply(objectValue, conditionValue);
            }

            if (listSpecificOperatorsFunctionMap.get(operator) != null)
                return listSpecificOperatorsFunctionMap.get(operator).apply(objectValues, conditionValue);

            return evaluateItemsInCollection(operator, conditionValue, objectValues, nestedJoinAttributes, filterField, fieldType);
        } catch (Exception e) {
            throw new RuleException("Condition is not set properly: " + e.getMessage());
        }
    }

    private boolean evaluateItemsInCollection(FilterConditionOperator operator, Object conditionValue, Collection<?> objectValues, List<Attribute> nestedJoinAttributes, FilterField filterField, FilterFieldType fieldType) throws InvocationTargetException, IllegalAccessException, NoSuchMethodException {
        // For EQUALS, if no true evaluation during loop, result stays false, for NOT_EQUALS, if there is no false evaluation during loop, result stays true
        boolean result = (operator == FilterConditionOperator.NOT_EQUALS);
        for (Object item : objectValues) {
            if (nestedJoinAttributes != null) {
                item = getPropertyValue(item, nestedJoinAttributes, filterField.getFieldAttribute());
            }

            boolean eval = Boolean.TRUE.equals(
                    fieldTypeToOperatorActionMap.get(fieldType).get(operator).apply(item, conditionValue)
            );

            // For EQUALS: succeed if any true
            // For NOT_EQUALS: fail if any false
            if ((operator == FilterConditionOperator.EQUALS && eval) ||
                    (operator == FilterConditionOperator.NOT_EQUALS && !eval)) {
                result = (operator == FilterConditionOperator.EQUALS);
                break;
            }
        }

        return result;
    }

    private boolean evaluateMetaAttributeConditionItem(Resource resource, String fieldIdentifier, UUID objectUuid, Object conditionValue, FilterConditionOperator operator) throws RuleException {
        // If the Field Source is Meta Attribute, we expect Field Identifier to be formatted as follows 'name|contentType', since there can be multiple Meta Attributes with the same name, the Content Type must be specified
        String[] parts = parseNameAndContentType(fieldIdentifier);
        AttributeContentType fieldAttributeContentType = parseAttributeContentType(parts[1]);
        String fieldIdentifierName = parts[0];
        // From all Metadata of the object, find those with matching Name and Content Type and evaluate condition on these, return true for the first satisfying entry, otherwise continue with next.
        // Note: negated operators are evaluated per entry (true if any entry satisfies them), which diverges from FilterPredicatesBuilder's NOT EXISTS semantics when the same meta attribute is contributed by multiple connectors.
        List<MetadataResponseDto> metadata = attributeEngine.getMappedMetadataContent(ObjectAttributeContentInfo.builder(resource, objectUuid).build());
        for (List<ResponseMetadata> responseMetadata : metadata.stream().map(MetadataResponseDto::getItems).toList()) {
            for (ResponseMetadata responseAttributeDto : responseMetadata) {
                if (Objects.equals(responseAttributeDto.getName(), fieldIdentifierName) && fieldAttributeContentType == responseAttributeDto.getContentType() && evaluateConditionOnAttribute(responseAttributeDto.getContent(), responseAttributeDto.getContentType(), conditionValue, operator))
                        return true;
            }
        }
        // If no entry has been evaluated as satisfying, the condition is not satisfied as a whole
        return false;
    }

    private boolean evaluateCustomAttributeConditionItem(Resource resource, UUID objectUuid, String fieldIdentifier, Object conditionValue, FilterConditionOperator operator) throws RuleException {
        // If source is Custom Attribute, Field Identifier is either formatted as 'name|contentType', or only as `name` since the content type is not needed
        String attributeName = fieldIdentifier.contains("|") ? parseNameAndContentType(fieldIdentifier)[0] : fieldIdentifier;
        List<ResponseAttribute> responseAttributes = attributeEngine.getObjectCustomAttributesContent(resource, objectUuid);
        ResponseAttributeV3 attributeToCompare = (ResponseAttributeV3) responseAttributes.stream().filter(rad -> Objects.equals(rad.getName(), attributeName)).findFirst().orElse(null);
        // Evaluate condition on each attribute content of the attribute, if at least one condition is evaluated as satisfied at least once, the condition is satisfied for the object
        return evaluateConditionOnAttribute(attributeToCompare == null ? null : attributeToCompare.getContent(), attributeToCompare == null ? null : attributeToCompare.getContentType(), conditionValue, operator);
    }

    @Override
    public void performActions(Trigger trigger, TriggerHistory triggerHistory, T object, Object data) throws RuleException {
        Class resourceClass = ResourceToClass.getClassByResource(trigger.getResource());
        if (resourceClass == null) {
            throw new RuleException("Unknown class for resource " + trigger.getResource().getLabel());
        }

        if (!resourceClass.isInstance(object)) {
            logger.debug("Trigger '{}' cannot be executed due to incompatible resource.", trigger.getName());
            return;
        }

        ResourceEvent event = null;
        if (triggerHistory.getTriggerAssociationUuid() != null) {
            event = triggerHistory.getTriggerAssociation().getEvent();
        }

        if (trigger.getActions() != null) {
            for (Action action : trigger.getActions()) {
                for (Execution execution : action.getExecutions()) {
                    try {
                        if (execution.getType() == ExecutionType.SET_FIELD) {
                            performSetFieldExecution(trigger.getResource(), execution, object);
                        } else {
                            performSendNotificationAction(trigger.getResource(), event, execution, object, data, triggerHistory);
                        }
                        logger.debug("Execution '{}' of action '{}' has been performed.", action.getName(), execution.getName());
                    } catch (Exception e) {
                        logger.debug("Execution '{}' of action '{}' has not been performed. Reason: {}", action.getName(), execution.getName(), e.getMessage());
                        TriggerHistoryRecord triggerHistoryRecord = triggerService.createTriggerHistoryRecord(triggerHistory.getUuid(), null, execution.getUuid(), e.getMessage());
                        triggerHistory.getRecords().add(triggerHistoryRecord);
                    }
                }
                logger.debug("Action '{}' has been performed.", action.getName());
            }
        }
    }

    private List<BaseAttributeContentV3<?>> resolveSourceAttributeContent(Resource resource, ExecutionItem executionItem, T object) throws RuleException {
        UUID objectUuid;
        try {
            objectUuid = (UUID) PropertyUtils.getProperty(object, "uuid");
        } catch (IllegalAccessException | InvocationTargetException | NoSuchMethodException e) {
            throw new RuleException("Cannot get uuid from resource " + resource + ".");
        }

        final String sourceName;
        String[] sourceParts = parseNameAndContentType(executionItem.getSourceFieldIdentifier());
        sourceName = sourceParts[0];
        final AttributeContentType sourceContentType = parseAttributeContentType(sourceParts[1]);
        FilterFieldSource sourceFieldSource = executionItem.getSourceFieldSource();

        List<BaseAttributeContentV3<?>> content = switch (sourceFieldSource) {
            case META -> {
                List<MetadataResponseDto> metadata = attributeEngine.getMappedMetadataContent(
                        ObjectAttributeContentInfo.builder(resource, objectUuid).build());
                yield metadata.stream()
                        .flatMap(m -> m.getItems().stream())
                        .filter(rm -> Objects.equals(rm.getName(), sourceName) && sourceContentType == rm.getContentType())
                        .findFirst()
                        .map(rm -> rm.getContent().stream()
                                .<BaseAttributeContentV3<?>>map(c -> AttributeVersionHelper.convertAttributeContentToV3(c, rm.getContentType()))
                                .toList())
                        .orElse(null);
            }
            case DATA -> {
                List<ResponseAttribute> dataAttrs = attributeEngine.getObjectDataAttributesContentUnversioned(resource, objectUuid);
                yield dataAttrs.stream()
                        .filter(ra -> Objects.equals(ra.getName(), sourceName) && sourceContentType == ra.getContentType())
                        .findFirst()
                        .map(ra -> ra.<List<AttributeContent>>getContent().stream()
                                .<BaseAttributeContentV3<?>>map(c -> AttributeVersionHelper.convertAttributeContentToV3(c, ra.getContentType()))
                                .toList())
                        .orElse(null);
            }
            case CUSTOM -> {
                List<ResponseAttribute> customAttrs = attributeEngine.getObjectCustomAttributesContent(resource, objectUuid);
                yield customAttrs.stream()
                        .filter(ra -> Objects.equals(ra.getName(), sourceName) && sourceContentType == ra.getContentType())
                        .findFirst()
                        .map(ra -> ((ResponseAttributeV3) ra).getContent())
                        .orElse(null);
            }
            default -> throw new RuleException("Unsupported sourceFieldSource: " + sourceFieldSource);
        };

        if (content == null) {
            throw new RuleException("Source attribute '" + sourceName + "' of type " + sourceFieldSource + " not found on object.");
        }
        return content;
    }

    protected void performSetFieldExecution(Resource resource, Execution execution, T object) throws RuleException, NotFoundException, AttributeException, CertificateOperationException {
        for (ExecutionItem executionItem : execution.getItems()) {
            String fieldIdentifier = executionItem.getFieldIdentifier();
            FilterFieldSource fieldSource = executionItem.getFieldSource();

            if (executionItem.getSourceFieldSource() != null) {
                List<BaseAttributeContentV3<?>> resolvedContent = resolveSourceAttributeContent(resource, executionItem, object);
                performSetFieldAttributeExecution(resource, fieldIdentifier, resolvedContent, object);
            } else {
                Object actionData = executionItem.getData();
                if (fieldSource == FilterFieldSource.PROPERTY) {
                    performSetFieldPropertyExecution(fieldIdentifier, actionData, object);
                } else if (fieldSource == FilterFieldSource.CUSTOM) {
                    performSetFieldAttributeExecution(resource, fieldIdentifier, actionData, object);
                }
            }
        }
    }

    protected void performSetFieldPropertyExecution(String fieldIdentifier, Object actionData, T object) throws RuleException, CertificateOperationException, NotFoundException, AttributeException {
        FilterField propertyEnum = Enum.valueOf(FilterField.class, fieldIdentifier);
        if (!propertyEnum.isSettable())
            throw new RuleException("Setting property '" + fieldIdentifier + "' is not supported.");
        try {
            PropertyUtils.setProperty(object, propertyEnum.getFieldAttribute().getName(), actionData);
        } catch (Exception e) {
            throw new RuleException(e.getMessage());
        }
    }

    protected void performSetFieldAttributeExecution(Resource resource, String fieldIdentifier, Object actionData, T object) throws RuleException, NotFoundException, AttributeException {
        performSetFieldAttributeExecution(resource, fieldIdentifier, AttributeDefinitionUtils.convertContentItemsFromObject(actionData), object);
    }

    private void performSetFieldAttributeExecution(Resource resource, String fieldIdentifier, List<BaseAttributeContentV3<?>> attributeContents, T object) throws RuleException, NotFoundException, AttributeException {
        UUID objectUuid;
        try {
            objectUuid = (UUID) PropertyUtils.getProperty(object, "uuid");
        } catch (IllegalAccessException | InvocationTargetException | NoSuchMethodException e) {
            throw new RuleException("Cannot get uuid from resource " + resource + ".");
        }
        if (objectUuid == null) {
            throw new RuleException("Cannot set custom attributes for an object not in database.");
        }
        attributeEngine.updateObjectCustomAttributeContent(resource, objectUuid, null,
                parseNameAndContentType(fieldIdentifier)[0], attributeContents);
    }

    protected void performSendNotificationAction(Resource resource, ResourceEvent event, Execution execution, T object, Object data, TriggerHistory triggerHistory) {
        List<UUID> notificationProfileUuids = new ArrayList<>();
        for (ExecutionItem executionItem : execution.getItems()) {
            notificationProfileUuids.add(executionItem.getNotificationProfileUuid());
        }

        NotificationMessage message = new NotificationMessage(event, resource, object.getUuid(), notificationProfileUuids, null, data, triggerHistory.getUuid(), execution.getUuid());
        // Delay publication until after the current transaction commits, so TriggerHistory is
        // visible to the NotificationListener when it creates TriggerHistoryRecords.
        applicationEventPublisher.publishEvent(message);
    }

    private Object getPropertyValue(Object object, List<Attribute> joinAttributes, Attribute fieldAttribute) throws InvocationTargetException, IllegalAccessException, NoSuchMethodException {
        String pathToProperty = FilterPredicatesBuilder.buildPathToProperty(joinAttributes, fieldAttribute);
        return PropertyUtils.getProperty(object, pathToProperty);
    }

    private boolean getConditionEvaluationResult(ConditionItem conditionItem, T object, TriggerHistory triggerHistory, Rule rule) {
        try {
            if (!evaluateConditionItem(conditionItem, object, rule.getResource())) {
                String message = String.format("Condition item '%s %s %s %s' is false.", conditionItem.getFieldSource().getLabel(), conditionItem.getFieldIdentifier(), conditionItem.getOperator().getLabel(), conditionItem.getValue() != null ? conditionItem.getValue().toString() : "");
                logger.debug("Rule {} is not satisfied. Reason: {}", rule.getName(), message);
                TriggerHistoryRecord triggerHistoryRecord = triggerService.createTriggerHistoryRecord(triggerHistory.getUuid(), conditionItem.getCondition().getUuid(), null, message);
                triggerHistory.getRecords().add(triggerHistoryRecord);
                return false;
            }
        } catch (RuleException e) {
            TriggerHistoryRecord triggerHistoryRecord = triggerService.createTriggerHistoryRecord(triggerHistory.getUuid(), conditionItem.getCondition().getUuid(), null, e.getMessage());
            triggerHistory.getRecords().add(triggerHistoryRecord);
            return false;
        }
        return true;
    }

    private static String[] parseNameAndContentType(String fieldIdentifier) throws RuleException {
        String[] parts = fieldIdentifier.split("\\|", 2);
        if (parts.length < 2 || parts[0].isEmpty() || parts[1].isEmpty()) {
            throw new RuleException("Field identifier is not in correct format 'name|contentType', got: " + fieldIdentifier);
        }
        return parts;
    }

    private static AttributeContentType parseAttributeContentType(String contentType) throws RuleException {
        try {
            return AttributeContentType.valueOf(contentType);
        } catch (IllegalArgumentException e) {
            throw new RuleException("Cannot parse content type %s from field identifier: %s".formatted(contentType, e.getMessage()));
        }
    }

    private static final Map<FilterConditionOperator, BiFunction<Object, Object, Boolean>> commonOperatorFunctionMap;
    private static final Map<FilterFieldType, Map<FilterConditionOperator, BiFunction<Object, Object, Boolean>>> fieldTypeToOperatorActionMap;
    private static final Map<FilterConditionOperator, BiFunction<Object, Object, Boolean>> stringOperatorFunctionMap;
    private static final Map<FilterConditionOperator, BiFunction<Object, Object, Boolean>> numberOperatorFunctionMap;
    private static final Map<FilterConditionOperator, BiFunction<Object, Object, Boolean>> listOperatorFunctionMap;
    private static final Map<FilterConditionOperator, BiFunction<Object, Object, Boolean>> dateOperatorFunctionMap;
    private static final Map<FilterConditionOperator, BiFunction<Object, Object, Boolean>> datetimeOperatorFunctionMap;

    private static final Map<FilterConditionOperator, BiFunction<Collection<?>, Object, Boolean>> listSpecificOperatorsFunctionMap =
            Map.of(
                    FilterConditionOperator.EMPTY, (list, value) -> list.isEmpty(),
                    FilterConditionOperator.NOT_EMPTY, (list, value) -> !list.isEmpty(),
                    FilterConditionOperator.COUNT_EQUAL, (list, value) -> list.size() == (int) value,
                    FilterConditionOperator.COUNT_NOT_EQUAL, (list, value) -> list.size() != (int) value,
                    FilterConditionOperator.COUNT_GREATER_THAN, (list, value) -> list.size() > (int) value,
                    FilterConditionOperator.COUNT_LESS_THAN, (list, value) -> list.size() < (int) value
            );


    static {
        commonOperatorFunctionMap = new EnumMap<>(FilterConditionOperator.class);
        commonOperatorFunctionMap.put(FilterConditionOperator.EQUALS, Object::equals);
        commonOperatorFunctionMap.put(FilterConditionOperator.NOT_EQUALS, (o, c) -> !o.equals(c));
        commonOperatorFunctionMap.put(FilterConditionOperator.EMPTY, (o, c) -> o == null);
        commonOperatorFunctionMap.put(FilterConditionOperator.NOT_EMPTY, (o, c) -> o != null);

        fieldTypeToOperatorActionMap = new EnumMap<>(FilterFieldType.class);

        stringOperatorFunctionMap = new EnumMap<>(FilterConditionOperator.class);
        stringOperatorFunctionMap.putAll(commonOperatorFunctionMap);
        stringOperatorFunctionMap.put(FilterConditionOperator.CONTAINS, (o, c) -> o.toString().contains(c.toString()));
        stringOperatorFunctionMap.put(FilterConditionOperator.NOT_CONTAINS, (o, c) -> !o.toString().contains(c.toString()));
        stringOperatorFunctionMap.put(FilterConditionOperator.STARTS_WITH, (o, c) -> o.toString().startsWith(c.toString()));
        stringOperatorFunctionMap.put(FilterConditionOperator.ENDS_WITH, (o, c) -> o.toString().endsWith(c.toString()));
        stringOperatorFunctionMap.put(FilterConditionOperator.MATCHES, (o, c) -> o.toString().matches(c.toString()));
        stringOperatorFunctionMap.put(FilterConditionOperator.NOT_MATCHES, (o, c) -> !o.toString().matches(c.toString()));

        fieldTypeToOperatorActionMap.put(FilterFieldType.STRING, stringOperatorFunctionMap);

        numberOperatorFunctionMap = new EnumMap<>(FilterConditionOperator.class);
        numberOperatorFunctionMap.putAll(commonOperatorFunctionMap);
        numberOperatorFunctionMap.put(FilterConditionOperator.EQUALS, (o, c) -> compareNumbers((Number) o, c) == 0);
        numberOperatorFunctionMap.put(FilterConditionOperator.NOT_EQUALS, (o, c) -> compareNumbers((Number) o, c) != 0);
        numberOperatorFunctionMap.put(FilterConditionOperator.GREATER, (o, c) -> compareNumbers((Number) o, c) > 0);
        numberOperatorFunctionMap.put(FilterConditionOperator.GREATER_OR_EQUAL, (o, c) -> compareNumbers((Number) o, c) > 0 || compareNumbers((Number) o, c) == 0);
        numberOperatorFunctionMap.put(FilterConditionOperator.LESSER, (o, c) -> compareNumbers((Number) o, c) < 0);
        numberOperatorFunctionMap.put(FilterConditionOperator.LESSER_OR_EQUAL, (o, c) -> compareNumbers((Number) o, c) < 0 || compareNumbers((Number) o, c) == 0);
        fieldTypeToOperatorActionMap.put(FilterFieldType.NUMBER, numberOperatorFunctionMap);

        dateOperatorFunctionMap = new EnumMap<>(FilterConditionOperator.class);
        dateOperatorFunctionMap.putAll(commonOperatorFunctionMap);
        dateOperatorFunctionMap.put(FilterConditionOperator.GREATER, (o, c) -> getLocalDate((Date) o).isAfter(LocalDate.parse(c.toString())));
        dateOperatorFunctionMap.put(FilterConditionOperator.GREATER_OR_EQUAL, (o, c) -> !(getLocalDate((Date) o).isBefore(LocalDate.parse(c.toString()))));
        dateOperatorFunctionMap.put(FilterConditionOperator.LESSER, (o, c) -> getLocalDate((Date) o).isBefore(LocalDate.parse(c.toString())));
        dateOperatorFunctionMap.put(FilterConditionOperator.LESSER_OR_EQUAL, (o, c) -> !(getLocalDate((Date) o).isAfter(LocalDate.parse(c.toString()))));
        dateOperatorFunctionMap.put(FilterConditionOperator.IN_PAST, (o, c) -> (getLocalDate((Date) o)).isBefore(LocalDate.now()) && (getLocalDate((Date) o)).isAfter(getLocalDateNowMinusDuration(c.toString())));
        dateOperatorFunctionMap.put(FilterConditionOperator.IN_NEXT, (o, c) -> (getLocalDate((Date) o)).isAfter(LocalDate.now()) && (getLocalDate((Date) o)).isBefore(getLocalDateNowPlusDuration(c.toString())));

        fieldTypeToOperatorActionMap.put(FilterFieldType.DATE, dateOperatorFunctionMap);

        datetimeOperatorFunctionMap = new EnumMap<>(FilterConditionOperator.class);
        datetimeOperatorFunctionMap.putAll(commonOperatorFunctionMap);
        datetimeOperatorFunctionMap.put(FilterConditionOperator.GREATER, (o, c) -> getLocalDateTime((Date) o).isAfter(LocalDateTime.parse(c.toString(), DateTimeFormatter.ofPattern(DATETIME_FORMAT))));
        datetimeOperatorFunctionMap.put(FilterConditionOperator.GREATER_OR_EQUAL, (o, c) -> !(getLocalDateTime((Date) o).isBefore(LocalDateTime.parse(c.toString(), DateTimeFormatter.ofPattern(DATETIME_FORMAT)))));
        datetimeOperatorFunctionMap.put(FilterConditionOperator.LESSER, (o, c) -> getLocalDateTime((Date) o).isBefore(LocalDateTime.parse(c.toString(), DateTimeFormatter.ofPattern(DATETIME_FORMAT))));
        datetimeOperatorFunctionMap.put(FilterConditionOperator.LESSER_OR_EQUAL, (o, c) -> !(getLocalDateTime((Date) o).isAfter(LocalDateTime.parse(c.toString(), DateTimeFormatter.ofPattern(DATETIME_FORMAT)))));
        datetimeOperatorFunctionMap.put(FilterConditionOperator.IN_PAST, (o, c) -> (getLocalDateTime((Date) o)).isBefore(LocalDateTime.now()) && (getLocalDateTime((Date) o)).isAfter(getLocalDateTimeNowMinusDuration(c.toString())));
        datetimeOperatorFunctionMap.put(FilterConditionOperator.IN_NEXT, (o, c) -> (getLocalDateTime((Date) o)).isAfter(LocalDateTime.now()) && (getLocalDateTime((Date) o)).isBefore(getLocalDateTimeNowPlusDuration(c.toString())));

        fieldTypeToOperatorActionMap.put(FilterFieldType.DATETIME, datetimeOperatorFunctionMap);

        listOperatorFunctionMap = new EnumMap<>(FilterConditionOperator.class);
        listOperatorFunctionMap.putAll(commonOperatorFunctionMap);
        listOperatorFunctionMap.put(FilterConditionOperator.EQUALS, (o, c) -> ((Collection<?>) c).contains(o));
        listOperatorFunctionMap.put(FilterConditionOperator.NOT_EQUALS, (o, c) -> !((Collection<?>) c).contains(o));
        fieldTypeToOperatorActionMap.put(FilterFieldType.LIST, listOperatorFunctionMap);

        fieldTypeToOperatorActionMap.put(FilterFieldType.BOOLEAN, commonOperatorFunctionMap);

    }

    private static LocalDate getLocalDate(Date o) {
        return o.toInstant().atZone(ZoneId.systemDefault()).toLocalDate();
    }

    private static LocalDateTime getLocalDateTime(Date o) {
        return o.toInstant().atZone(ZoneId.systemDefault()).toLocalDateTime();
    }

    private static LocalDateTime getLocalDateTimeNowMinusDuration(String duration) {
        Duration durationParsed = getDurationParsed(duration);
        return LocalDateTime.now().minus(Period.of(durationParsed.getYears(), durationParsed.getMonths(), durationParsed.getDays()))
                .minusHours(durationParsed.getHours()).minusMinutes(durationParsed.getMinutes()).minusSeconds(durationParsed.getSeconds());
    }

    private static LocalDate getLocalDateNowMinusDuration(String duration) {
        Duration durationParsed = getDurationParsed(duration);
        return LocalDate.now().minus(Period.of(durationParsed.getYears(), durationParsed.getMonths(), durationParsed.getDays()));
    }

    private static LocalDateTime getLocalDateTimeNowPlusDuration(String duration) {
        Duration durationParsed = getDurationParsed(duration);
        return LocalDateTime.now().plus(Period.of(durationParsed.getYears(), durationParsed.getMonths(), durationParsed.getDays()))
                .plusHours(durationParsed.getHours()).plusMinutes(durationParsed.getMinutes()).plusSeconds(durationParsed.getSeconds());
    }

    private static LocalDate getLocalDateNowPlusDuration(String duration) {
        Duration durationParsed = getDurationParsed(duration);
        return LocalDate.now().plus(Period.of(durationParsed.getYears(), durationParsed.getMonths(), durationParsed.getDays()));
    }

    private static Duration getDurationParsed(String duration) {
        Duration durationParsed;
        try {
            durationParsed = DatatypeFactory.newInstance().newDuration(duration);
        } catch (Exception e) {
            throw new ValidationException("Cannot parse " + duration + "to Duration: " + e.getMessage());
        }
        return durationParsed;
    }

    private static int compareNumbers(Number objectNumber, Object conditionNumber) {
        if (conditionNumber instanceof String) {
            conditionNumber = Float.parseFloat(conditionNumber.toString());
        } else if (!(conditionNumber instanceof Number)) {
            throw new ValidationException("Invalid type for conditionNumber. Expected String or Number, but got: "
                    + (conditionNumber == null ? "null" : conditionNumber.getClass().getSimpleName()));
        }
        return Float.compare(objectNumber.floatValue(), ((Number) conditionNumber).floatValue());
    }

    private boolean evaluateConditionOnAttribute(List<? extends AttributeContent> content, AttributeContentType contentType, Object conditionValue, FilterConditionOperator operator) throws RuleException {
        boolean missingContent = content == null || content.isEmpty();
        if (operator == FilterConditionOperator.EMPTY) {
            return missingContent;
        }
        if (operator == FilterConditionOperator.NOT_EMPTY) {
            return !missingContent;
        }

        // For negated operators, evaluate the positive counterpart across all items and negate the result:
        // "none of the items satisfies EQUALS/CONTAINS/MATCHES" — mirrors FilterPredicatesBuilder's NOT EXISTS semantics.
        FilterConditionOperator effectiveOperator = switch (operator) {
            case NOT_EQUALS -> FilterConditionOperator.EQUALS;
            case NOT_CONTAINS -> FilterConditionOperator.CONTAINS;
            case NOT_MATCHES -> FilterConditionOperator.MATCHES;
            default -> operator;
        };
        boolean isNegated = effectiveOperator != operator;

        // For negated operators, attributes without content also match the operator, mirroring FilterPredicatesBuilder's NOT EXISTS semantics.
        if (isNegated && missingContent) {
            return true;
        }
        // For non-negated operators, attributes without content do not match the operator.
        if (missingContent) return false;

        // If the attribute is a list, iterate through each item and short-circuit on the first definitive result.
        // If the attribute is not a list, there is only one item in the content list, so only one check will be done.
        for (AttributeContent attributeContent : content) {
            Object attributeValue = contentType.isFilterByData() ? attributeContent.getData() : attributeContent.getReference();
            try {
                if (Boolean.TRUE.equals(fieldTypeToOperatorActionMap.get(contentTypeToFieldType(contentType)).get(effectiveOperator).apply(attributeValue, conditionValue)))
                    // Positive match found: for non-negated ops return true, for negated ops return false (a match disqualifies NOT_EQUALS/NOT_CONTAINS/NOT_MATCHES)
                    return !isNegated;
            } catch (Exception e) {
                throw new RuleException("Cannot evaluate operator %s with condition value '%s' (contentType: %s): %s"
                        .formatted(operator, conditionValue, contentType, e.getMessage()));
            }
        }
        // No positive match found: for non-negated ops return false, for negated ops return true
        return isNegated;
    }


    private FilterFieldType contentTypeToFieldType(AttributeContentType contentType) {
        switch (contentType) {
            case STRING, TEXT, CODEBLOCK, SECRET, FILE, CREDENTIAL, OBJECT, RESOURCE -> {
                return FilterFieldType.STRING;
            }
            case INTEGER, FLOAT -> {
                return FilterFieldType.NUMBER;
            }
            case BOOLEAN -> {
                return FilterFieldType.BOOLEAN;
            }
            case DATE -> {
                return FilterFieldType.DATE;
            }
            case TIME, DATETIME -> {
                return FilterFieldType.DATETIME;
            }
        }
        return null;
    }


}

