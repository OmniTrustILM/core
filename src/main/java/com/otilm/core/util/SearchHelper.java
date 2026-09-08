package com.otilm.core.util;

import com.otilm.api.model.common.attribute.common.content.AttributeContentType;
import com.otilm.api.model.common.attribute.common.content.data.ProtectionLevel;
import com.otilm.api.model.common.enums.BitMaskEnum;
import com.otilm.api.model.common.enums.IPlatformEnum;
import com.otilm.api.model.common.enums.PlatformEnum;
import com.otilm.api.model.core.auth.Resource;
import com.otilm.api.model.core.search.FilterConditionOperator;
import com.otilm.api.model.core.search.FilterFieldType;
import com.otilm.api.model.core.search.SearchFieldDataDto;
import com.otilm.core.attribute.engine.AttributeColumnProjector;
import com.otilm.core.comparator.SearchFieldDataComparator;
import com.otilm.core.enums.FilterField;
import com.otilm.core.enums.SearchFieldTypeEnum;
import com.otilm.core.model.SearchFieldObject;
import jakarta.persistence.metamodel.Attribute;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Comparator;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;
import java.util.stream.Stream;

public class SearchHelper {

    private static final String SEARCH_LABEL_TEMPLATE = "%s (%s)";

    /**
     * Fields that share one attribute with another field of the same resource, and so display something drawn out of it
     * rather than the attribute itself. Derived rather than listed, so a field added later is classified without an
     * edit here: the certificate validation-check fields are the case that exists today, each reading one serialized
     * validation result.
     *
     * <p>
     * Held in a nested class so it is computed on first use rather than when {@link SearchHelper} loads. Reading it
     * initializes {@link FilterField}, whose entries reference the JPA static metamodel, so a caller without a
     * persistence context would otherwise fail on this class rather than on the field it asked about.
     */
    private static final class SharedAttributeFields {

        private static final Set<FilterField> VALUES = fieldsSharingAnAttribute();

        private SharedAttributeFields() {
        }
    }

    private static Set<FilterField> fieldsSharingAnAttribute() {
        Map<List<Object>, List<FilterField>> byAttribute = Arrays
                .stream(FilterField.values())
                .filter(field -> field.getFieldAttribute() != null)
                .collect(Collectors.groupingBy(field -> List.of(field.getRootResource(), field.getFieldAttribute())));

        return byAttribute
                .values()
                .stream()
                .filter(group -> group.size() > 1)
                .flatMap(List::stream)
                .collect(Collectors.toUnmodifiableSet());
    }

    public static SearchFieldDataDto prepareSearch(final FilterField fieldNameEnum) {
        return prepareSearch(fieldNameEnum, null);
    }

    public static SearchFieldDataDto prepareSearch(final FilterField filterField, Object values) {
        final SearchFieldDataDto fieldDataDto = new SearchFieldDataDto();
        fieldDataDto.setFieldIdentifier(filterField.name());
        fieldDataDto.setFieldLabel(filterField.getLabel());
        fieldDataDto.setMultiValue(filterField.getType().isMultiValue());
        fieldDataDto.setConditions(availableConditions(filterField));
        fieldDataDto.setType(filterField.getType().getFieldType());
        // Do not add null value to List filter. A NATIVE_ARRAY field reports FilterFieldType.LIST but is not
        // SearchFieldTypeEnum.LIST, so its caller takes the single-value path and supplies no values at all --
        // there is then nothing to strip, and casting the absent value to a List throws.
        if (filterField.getType().getFieldType() == FilterFieldType.LIST && filterField.getEnumClass() == null
                && values instanceof List<?> suppliedValues) {
            List<Object> withoutNull = new ArrayList<>(suppliedValues);
            withoutNull.remove(null);
            values = withoutNull;
        }
        fieldDataDto.setValue(values);
        fieldDataDto.setDisplayable(true);
        fieldDataDto.setSortable(isSortable(filterField));

        if (filterField.getEnumClass() != null) {
            fieldDataDto.setPlatformEnum(PlatformEnum.findByClass(filterField.getEnumClass()));
            if (values == null) {
                fieldDataDto
                        .setValue(Arrays
                                .stream(fieldDataDto.getPlatformEnum().getEnumClass().getEnumConstants())
                                .map(IPlatformEnum::getCode)
                                .sorted()
                                .toList());
            }
        }

        return fieldDataDto;
    }

    /**
     * The conditions a property field accepts, which is what the listing endpoint advertises for it. Callers that only
     * need the operator set - validating a stored filter, for one - can ask for it without assembling the field's
     * available values.
     */
    public static List<FilterConditionOperator> availableConditions(final FilterField filterField) {
        // A FREE_TEXT field has no single attribute by design (it spans several columns), so the
        // null-attribute downgrade to presence-only conditions must not apply to it.
        boolean presenceOnly = filterField.getFieldAttribute() == null
                && filterField.getType() != SearchFieldTypeEnum.FREE_TEXT;
        List<FilterConditionOperator> conditionOperators = presenceOnly
                ? new ArrayList<>(List.of(FilterConditionOperator.EMPTY, FilterConditionOperator.NOT_EMPTY))
                : new ArrayList<>(getInitialCapacity(filterField));

        if (filterField.getType() == SearchFieldTypeEnum.LIST && filterField.getJoinAttributes() != null
                && filterField.getJoinAttributes().stream().anyMatch(Attribute::isCollection)) {
            conditionOperators
                    .addAll(List
                            .of(FilterConditionOperator.COUNT_EQUAL, FilterConditionOperator.COUNT_NOT_EQUAL,
                                    FilterConditionOperator.COUNT_GREATER_THAN,
                                    FilterConditionOperator.COUNT_LESS_THAN));
        }
        return conditionOperators;
    }

    private static List<FilterConditionOperator> getInitialCapacity(FilterField filterField) {
        if (filterField.getJsonPath() != null && FilterPredicatesBuilder.isJsonArray(filterField)) {
            return List
                    .of(FilterConditionOperator.EQUALS, FilterConditionOperator.NOT_EQUALS,
                            FilterConditionOperator.EMPTY, FilterConditionOperator.NOT_EMPTY);
        }
        return filterField.getType().getFieldType() == FilterFieldType.BOOLEAN && filterField.getExpectedValue() != null
                ? List.of(FilterConditionOperator.EQUALS, FilterConditionOperator.NOT_EQUALS)
                : filterField.getType().getConditions();
    }

    public static SearchFieldDataDto prepareSearchForJSON(final SearchFieldObject attributeSearchInfo,
            final boolean hasDuplicateInList, final Resource resource) {
        final SearchFieldTypeEnum searchFieldTypeEnum = retrieveSearchFieldTypeEnumByContentType(
                attributeSearchInfo.getAttributeContentType(), attributeSearchInfo.isList());
        final SearchFieldDataDto fieldDataDto = new SearchFieldDataDto();
        fieldDataDto.setFieldIdentifier(buildFieldIdentifier(attributeSearchInfo));
        fieldDataDto
                .setFieldLabel(hasDuplicateInList
                        ? String
                                .format(SEARCH_LABEL_TEMPLATE, attributeSearchInfo.getLabel(),
                                        attributeSearchInfo.getAttributeContentType().getCode())
                        : attributeSearchInfo.getLabel());
        fieldDataDto.setMultiValue(attributeSearchInfo.isMultiSelect());
        List<FilterConditionOperator> conditionOperators = new ArrayList<>(searchFieldTypeEnum.getConditions());
        if (attributeSearchInfo.getAttributeContentType() == AttributeContentType.TIME) {
            conditionOperators.removeAll(List.of(FilterConditionOperator.IN_NEXT, FilterConditionOperator.IN_PAST));
        }
        // Content no response renders answers only whether a value is present: ciphertext no listing can decrypt, and
        // the content types AttributeColumnProjector withholds outright. Offering a value condition would publish a
        // filter the listing then refuses.
        if (attributeSearchInfo.getProtectionLevel() == ProtectionLevel.ENCRYPTED
                || AttributeColumnProjector.WITHHELD_CONTENT_TYPES
                        .contains(attributeSearchInfo.getAttributeContentType())) {
            conditionOperators = List.of(FilterConditionOperator.EMPTY, FilterConditionOperator.NOT_EMPTY);
        }
        fieldDataDto.setConditions(conditionOperators);
        fieldDataDto.setType(searchFieldTypeEnum.getFieldType());
        fieldDataDto.setValue(attributeSearchInfo.getContentItems());
        fieldDataDto.setAttributeContentType(attributeSearchInfo.getAttributeContentType());
        fieldDataDto.setDisplayable(isDisplayable(attributeSearchInfo));
        fieldDataDto.setSortable(isSortable(attributeSearchInfo, resource));
        return fieldDataDto;
    }

    /**
     * The resources whose listing passes the sort a request carries to the repository.
     *
     * <p>
     * The flag is published per field while the ordering is wired per listing, and only the listings named here are
     * wired. A field of any other resource is reported not sortable however orderable its path is, because a catalogue
     * reporting {@code true} there would advertise an ordering that listing discards: the client sorts, receives the
     * default order, and is told nothing.
     *
     * <p>
     * Explicit rather than derived: the wiring lives in each listing service and nothing on a {@link FilterField} knows
     * whether its listing was wired. A listing that gains ordering adds itself here, and
     * {@code RequestValidatorHelper.revalidateSearchRequestDto} refuses a sort on every listing that has not.
     */
    private static final Set<Resource> SORT_WIRED_RESOURCES = Set
            .of(Resource.CERTIFICATE, Resource.CRYPTOGRAPHIC_KEY, Resource.DISCOVERY, Resource.CONNECTOR,
                    Resource.SECRET, Resource.CBOM, Resource.SIGNING_RECORD);

    /**
     * Content whose column renders a composite identity rather than the value a sort key would read.
     *
     * <p>
     * A sort key extracts the stored {@code reference} for content that is not filtered by data. For most such types
     * that is exactly what the cell shows - {@code AttributeColumnProjector} reduces CREDENTIAL and OBJECT values to
     * their reference and nothing else. FILE and RESOURCE are the exceptions: the projector keeps a reduced identity
     * beside the reference, and the cell labels itself from that - a file by its name and media type, a resource link
     * by the referenced object's name - so ordering by the reference would order the page by something no cell shows.
     */
    private static final Set<AttributeContentType> COMPOSITE_CELL_CONTENT_TYPES = Set
            .of(AttributeContentType.FILE, AttributeContentType.RESOURCE);

    /**
     * Whether the listing of this resource applies the sort a request carries.
     */
    public static boolean listingAppliesSort(final Resource resource) {
        return SORT_WIRED_RESOURCES.contains(resource);
    }

    /**
     * What the catalogue advertises as sortable for an attribute field: a field the catalogue offers as a column at
     * all, whose value is what its cell shows, on a listing that applies the ordering.
     *
     * <p>
     * Decided here rather than by a pass over the assembled catalogue, so it is answered wherever {@code displayable}
     * is and no caller can assemble a catalogue that forgets to answer it.
     */
    private static boolean isSortable(final SearchFieldObject attributeSearchInfo, final Resource resource) {
        return listingAppliesSort(resource) && isDisplayable(attributeSearchInfo)
                && !COMPOSITE_CELL_CONTENT_TYPES.contains(attributeSearchInfo.getAttributeContentType());
    }

    /**
     * What the catalogue advertises as sortable: a field whose path can be ordered by, on a listing that applies the
     * ordering.
     */
    private static boolean isSortable(final FilterField filterField) {
        return SORT_WIRED_RESOURCES.contains(filterField.getRootResource()) && isOrderableField(filterField);
    }

    /**
     * Whether a sort on a property field would order by the value the column shows.
     *
     * <p>
     * A sort resolves to one scalar path from the queried root, so a field with no attribute behind it has nothing to
     * order by; a native array holds many values per row rather than one; and a JSON-path field's attribute is the
     * whole JSONB column, which would order by the serialized document instead of by the value the field names.
     *
     * <p>
     * A derived field is excluded for the same reason, even though its attribute is a scalar: what it displays is not
     * what that attribute holds. A field with an expected value displays a comparison against it rather than the value
     * itself - {@code PRIVATE_KEY} shows whether a joined key type is one particular type - and the certificate
     * validation-check fields each name one check inside a single serialized validation result, so ordering by the
     * attribute would order them all by the whole document.
     *
     * <p>
     * A bitmask-backed field is the same case once more: {@code KEY_USAGE} and {@code CKI_USAGE} persist a set of flags
     * as one integer, and the column renders the decoded set, so ordering by the column would order the page by a
     * number whose value bears no relation to the list in the cell.
     */
    public static boolean isOrderableField(final FilterField filterField) {
        return filterField.getFieldAttribute() != null && !filterField.isNativeArrayField()
                && filterField.getJsonPath() == null && filterField.getExpectedValue() == null
                && !isBitMaskField(filterField) && !SharedAttributeFields.VALUES.contains(filterField);
    }

    /** Whether the field's column is one integer holding a set of flags rather than the value the cell renders. */
    private static boolean isBitMaskField(final FilterField filterField) {
        return filterField.getEnumClass() != null && BitMaskEnum.class.isAssignableFrom(filterField.getEnumClass());
    }

    /**
     * Whether an attribute field may be requested as a column.
     *
     * <p>
     * Four kinds of field are withheld. A secret is never rendered anywhere. Encrypted content is stored as ciphertext
     * that only its own decryption path can read, and a listing does not take that path. A code block is multi-line by
     * construction - the frontend renders it as a block element - so a single-line table cell cannot hold one without
     * breaking the row. And an attribute whose definition is marked not visible is one the contract says to hide from
     * the user, which rules out putting its values in a column of their own.
     */
    private static boolean isDisplayable(final SearchFieldObject attributeSearchInfo) {
        return !AttributeColumnProjector.WITHHELD_CONTENT_TYPES.contains(attributeSearchInfo.getAttributeContentType())
                && attributeSearchInfo.getProtectionLevel() != ProtectionLevel.ENCRYPTED
                && attributeSearchInfo.isVisible();
    }

    private static SearchFieldTypeEnum retrieveSearchFieldTypeEnumByContentType(
            AttributeContentType attributeContentType, boolean isList) {
        if (isList) {
            return SearchFieldTypeEnum.LIST;
        }

        SearchFieldTypeEnum searchFieldTypeEnum = null;
        switch (attributeContentType) {
            case DATE, DATETIME, TIME -> searchFieldTypeEnum = SearchFieldTypeEnum.DATE;
            case INTEGER, FLOAT -> searchFieldTypeEnum = SearchFieldTypeEnum.NUMBER;
            case BOOLEAN -> searchFieldTypeEnum = SearchFieldTypeEnum.BOOLEAN;
            default -> searchFieldTypeEnum = SearchFieldTypeEnum.STRING;
        }
        return searchFieldTypeEnum;
    }

    /**
     * The catalogue entries for one resource's attribute fields. The resource is what decides {@code sortable}, since
     * ordering is wired per listing while the flag is published per field.
     */
    public static List<SearchFieldDataDto> prepareSearchForJSON(final List<SearchFieldObject> searchFieldObjectList,
            final Resource resource) {
        final List<SearchFieldObject> mergedFields = mergeFieldsWithSameIdentifier(searchFieldObjectList);
        final Set<String> duplicatesOfNames = filterDuplicity(mergedFields);
        return mergedFields
                .stream()
                .map(attribute -> prepareSearchForJSON(attribute,
                        duplicatesOfNames.contains(attribute.getAttributeName()), resource))
                .sorted(new SearchFieldDataComparator())
                .toList();
    }

    private static String buildFieldIdentifier(final SearchFieldObject attributeSearchInfo) {
        return attributeSearchInfo.getAttributeName() + "|" + attributeSearchInfo.getAttributeContentType().name();
    }

    // Total order over every merge-relevant field: the repository UNION carries no ORDER BY, so duplicates must be
    // sorted before merging to keep first-wins picks (label, content item order) stable across calls. Content items
    // are flattened with a NUL separator so distinct lists cannot collide into a tie.
    private static final Comparator<SearchFieldObject> DUPLICATE_MERGE_ORDER = Comparator
            .comparing(SearchHelper::buildFieldIdentifier)
            .thenComparing(SearchFieldObject::getLabel, Comparator.nullsLast(Comparator.naturalOrder()))
            .thenComparing(SearchFieldObject::isList)
            .thenComparing(SearchFieldObject::isMultiSelect)
            .thenComparing(SearchFieldObject::isVisible)
            .thenComparing(SearchFieldObject::getProtectionLevel, Comparator.nullsLast(Comparator.naturalOrder()))
            .thenComparing(field -> field.getContentItems() == null ? null : String.join("\0", field.getContentItems()),
                    Comparator.nullsLast(Comparator.naturalOrder()));

    /**
     * Collapses attribute search fields that map to the same field identifier (attribute name and content type). The
     * same attribute may be registered by multiple connectors, or by one connector repeatedly under new attribute
     * UUIDs, yielding one definition row each. Filtering matches the content of all such definitions by name and
     * content type, so they must be exposed as a single field with the union of their capabilities.
     */
    private static List<SearchFieldObject> mergeFieldsWithSameIdentifier(
            final List<SearchFieldObject> searchFieldObjectList) {
        final List<SearchFieldObject> orderedFields = searchFieldObjectList
                .stream()
                .sorted(DUPLICATE_MERGE_ORDER)
                .toList();
        final Map<String, SearchFieldObject> mergedFields = new LinkedHashMap<>();
        for (final SearchFieldObject field : orderedFields) {
            mergedFields.merge(buildFieldIdentifier(field), field, SearchHelper::mergeDuplicateField);
        }
        return new ArrayList<>(mergedFields.values());
    }

    private static SearchFieldObject mergeDuplicateField(final SearchFieldObject merged,
            final SearchFieldObject other) {
        // Value-based operators stay available if at least one definition is not encrypted; only its plain content is
        // matchable.
        if (other.getProtectionLevel() != ProtectionLevel.ENCRYPTED) {
            merged.setProtectionLevel(other.getProtectionLevel());
        }
        // Projection and the filter predicates keep the content of every visible definition, so the collapsed field is
        // shown whenever any definition behind it is visible.
        if (other.isVisible()) {
            merged.setVisible(true);
        }
        // A fixed-choice list input is only correct if every definition is a list; otherwise free-form input must
        // survive the merge, since a list rendering would make the free-form definitions' values un-enterable.
        if (!other.isList()) {
            merged.setList(false);
            merged.setMultiSelect(false);
            merged.setContentItems(null);
        } else if (merged.isList()) {
            if (other.isMultiSelect()) {
                merged.setMultiSelect(true);
            }
            if (other.getContentItems() != null) {
                merged
                        .setContentItems(merged.getContentItems() == null
                                ? other.getContentItems()
                                : Stream
                                        .concat(merged.getContentItems().stream(), other.getContentItems().stream())
                                        .distinct()
                                        .toList());
            }
        }
        return merged;
    }

    private static Set<String> filterDuplicity(final List<SearchFieldObject> searchFieldObjectList) {
        final Set<String> uniqueNames = new HashSet<>();
        final Set<String> duplicatesOfNames = new HashSet<>();
        for (final SearchFieldObject attr : searchFieldObjectList) {
            if (!uniqueNames.add(attr.getAttributeName())) {
                duplicatesOfNames.add(attr.getAttributeName());
            }
        }
        return duplicatesOfNames;
    }

}
