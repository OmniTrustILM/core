package com.otilm.core.service.impl;

import com.otilm.api.exception.ValidationException;
import com.otilm.api.model.client.certificate.SearchFilterRequestDto;
import com.otilm.api.model.core.auth.Resource;
import com.otilm.api.model.core.listview.ListViewFilterDto;
import com.otilm.api.model.core.oid.OidCategory;
import com.otilm.api.model.core.oid.SystemOid;
import com.otilm.api.model.core.search.FilterConditionOperator;
import com.otilm.api.model.core.search.FilterFieldSource;
import com.otilm.api.model.core.workflows.ConditionItemRequestDto;
import com.otilm.core.enums.FilterField;
import com.otilm.core.model.auth.ResourceAction;
import com.otilm.core.oid.OidHandler;
import com.otilm.core.oid.OidRecord;
import com.otilm.core.security.authz.AuthorizationEnforcer;
import java.io.Serializable;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;

/**
 * Resolves Extended Key Usage purpose names to the OIDs certificates store. A standard purpose is found by its name or
 * display name; a registered custom purpose by its display name, and only for a caller who may list OIDs. A caller who
 * may not gets the same refusal for a custom name as for a name nobody registered, so the registry cannot be probed.
 */
@Service
public class ExtendedKeyUsageFilterNormalizer {

    private static final String NOT_A_PURPOSE = "Extended Key Usage filter value must be an OID or a registered purpose: ";

    private final AuthorizationEnforcer authorizationEnforcer;

    public ExtendedKeyUsageFilterNormalizer(AuthorizationEnforcer authorizationEnforcer) {
        this.authorizationEnforcer = authorizationEnforcer;
    }

    @Transactional(propagation = Propagation.NOT_SUPPORTED)
    public List<SearchFilterRequestDto> normalize(List<SearchFilterRequestDto> filters) {
        if (filters == null) {
            return null;
        }
        List<SearchFilterRequestDto> normalized = new ArrayList<>(filters.size());
        for (SearchFilterRequestDto filter : filters) {
            normalized
                    .add(matchesPurposes(filter.getFieldSource(), filter.getFieldIdentifier(), filter.getCondition(),
                            filter.getValue())
                                    ? new SearchFilterRequestDto(filter.getFieldSource(), filter.getFieldIdentifier(),
                                            filter.getCondition(), (Serializable) resolveValue(filter.getValue(), true))
                                    : filter);
        }
        return normalized;
    }

    /**
     * The filters of a saved list view, resolved the same way; each keeps its {@code rebind}. Only a certificate view
     * has the field, so another resource's filters are returned as they are and its catalogue refuses the field.
     */
    @Transactional(propagation = Propagation.NOT_SUPPORTED)
    public List<ListViewFilterDto> normalizeViewFilters(Resource resource, List<ListViewFilterDto> filters) {
        if (filters == null || resource != FilterField.EXTENDED_KEY_USAGE.getRootResource()) {
            return filters;
        }
        List<ListViewFilterDto> normalized = new ArrayList<>(filters.size());
        for (ListViewFilterDto filter : filters) {
            if (!matchesPurposes(filter.getFieldSource(), filter.getFieldIdentifier(), filter.getCondition(),
                    filter.getValue())) {
                normalized.add(filter);
                continue;
            }
            ListViewFilterDto resolved = new ListViewFilterDto(filter.getFieldSource(), filter.getFieldIdentifier(),
                    filter.getCondition(), (Serializable) resolveValue(filter.getValue(), true));
            resolved.setRebind(filter.getRebind());
            normalized.add(resolved);
        }
        return normalized;
    }

    /**
     * The value a rule condition stores. Conditions are evaluated against the OIDs a certificate holds, so a standard
     * purpose name is stored as its OID. A custom purpose is named by its OID: resolving its display name would need
     * the caller's OID permission inside the transaction that saves the rule.
     */
    public Object normalizeConditionValue(ConditionItemRequestDto item) {
        return matchesPurposes(item.getFieldSource(), item.getFieldIdentifier(), item.getOperator(), item.getValue())
                ? resolveValue(item.getValue(), false)
                : item.getValue();
    }

    private static boolean matchesPurposes(FilterFieldSource fieldSource, String fieldIdentifier,
            FilterConditionOperator condition, Object value) {
        return fieldSource == FilterFieldSource.PROPERTY
                && FilterField.EXTENDED_KEY_USAGE.name().equals(fieldIdentifier)
                && (condition == FilterConditionOperator.EQUALS || condition == FilterConditionOperator.NOT_EQUALS)
                && value != null;
    }

    private Object resolveValue(Object value, boolean customNames) {
        return value instanceof List<?> values
                ? new ArrayList<>(values.stream().map(item -> resolve(String.valueOf(item), customNames)).toList())
                : resolve(value.toString(), customNames);
    }

    private String resolve(String value, boolean customNames) {
        if (OidHandler.isOid(value)) {
            return value;
        }
        String normalized = normalizeName(value);
        List<String> systemMatches = Arrays
                .stream(SystemOid.values())
                .filter(oid -> oid.getCategory() == OidCategory.EXTENDED_KEY_USAGE)
                .filter(oid -> normalizeName(oid.name()).equalsIgnoreCase(normalized)
                        || normalizeName(oid.getDisplayName()).equalsIgnoreCase(normalized))
                .map(SystemOid::getOid)
                .distinct()
                .toList();
        if (!systemMatches.isEmpty()) {
            return uniqueMatch(value, systemMatches);
        }
        if (!customNames) {
            throw new ValidationException(
                    "Extended Key Usage condition value must be an OID or a standard purpose name; name a custom "
                            + "purpose by its OID: " + value);
        }
        if (!mayListOids()) {
            return uniqueMatch(value, List.of());
        }
        Map<String, OidRecord> registered = OidHandler.getOidCache(OidCategory.EXTENDED_KEY_USAGE);
        List<String> customMatches = registered == null
                ? List.of()
                : registered
                        .entrySet()
                        .stream()
                        .filter(entry -> normalizeName(entry.getValue().displayName()).equalsIgnoreCase(normalized))
                        .map(Map.Entry::getKey)
                        .distinct()
                        .toList();
        return uniqueMatch(value, customMatches);
    }

    private boolean mayListOids() {
        try {
            authorizationEnforcer.enforce(Resource.OID, ResourceAction.LIST);
            return true;
        } catch (AccessDeniedException e) {
            return false;
        }
    }

    private static String normalizeName(String value) {
        return value.replaceAll("[\\s_-]", "");
    }

    private static String uniqueMatch(String value, List<String> matches) {
        if (matches.isEmpty()) {
            throw new ValidationException(NOT_A_PURPOSE + value);
        }
        if (matches.size() > 1) {
            throw new ValidationException("Extended Key Usage filter name is ambiguous; use an OID: " + value);
        }
        return matches.getFirst();
    }
}
