package com.otilm.core.service.impl;

import com.otilm.api.exception.ValidationException;
import com.otilm.api.model.client.certificate.SearchFilterRequestDto;
import com.otilm.api.model.core.auth.Resource;
import com.otilm.api.model.core.oid.OidCategory;
import com.otilm.api.model.core.oid.SystemOid;
import com.otilm.api.model.core.search.FilterConditionOperator;
import com.otilm.api.model.core.search.FilterFieldSource;
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
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;

@Service
public class ExtendedKeyUsageFilterNormalizer {

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
            if (filter.getFieldSource() != FilterFieldSource.PROPERTY
                    || !FilterField.EXTENDED_KEY_USAGE.name().equals(filter.getFieldIdentifier())
                    || (filter.getCondition() != FilterConditionOperator.EQUALS
                            && filter.getCondition() != FilterConditionOperator.NOT_EQUALS)
                    || filter.getValue() == null) {
                normalized.add(filter);
                continue;
            }

            Serializable value = filter.getValue();
            Serializable resolved = value instanceof List<?> values
                    ? new ArrayList<>(values.stream().map(item -> resolve(item.toString())).toList())
                    : resolve(value.toString());
            normalized
                    .add(new SearchFilterRequestDto(filter.getFieldSource(), filter.getFieldIdentifier(),
                            filter.getCondition(), resolved));
        }
        return normalized;
    }

    private String resolve(String value) {
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

        authorizationEnforcer.enforce(Resource.OID, ResourceAction.LIST);
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

    private static String normalizeName(String value) {
        return value.replaceAll("[\\s_-]", "");
    }

    private static String uniqueMatch(String value, List<String> matches) {
        if (matches.isEmpty()) {
            throw new ValidationException(
                    "Extended Key Usage filter value must be an OID or a registered purpose: " + value);
        }
        if (matches.size() > 1) {
            throw new ValidationException("Extended Key Usage filter name is ambiguous; use an OID: " + value);
        }
        return matches.getFirst();
    }
}
