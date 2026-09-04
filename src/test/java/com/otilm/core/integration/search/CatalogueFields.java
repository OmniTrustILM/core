package com.otilm.core.integration.search;

import com.otilm.api.model.core.search.FilterFieldSource;
import com.otilm.api.model.core.search.SearchFieldDataByGroupDto;
import com.otilm.api.model.core.search.SearchFieldDataDto;
import java.util.List;
import java.util.Optional;

/** Reads fields out of a published column catalogue, which arrives grouped by source. */
final class CatalogueFields {

    private CatalogueFields() {
    }

    static Optional<SearchFieldDataDto> field(List<SearchFieldDataByGroupDto> catalogue, String identifier) {
        return allFields(catalogue).stream().filter(item -> identifier.equals(item.getFieldIdentifier())).findFirst();
    }

    static List<SearchFieldDataDto> allFields(List<SearchFieldDataByGroupDto> catalogue) {
        return catalogue.stream().flatMap(group -> group.getSearchFieldData().stream()).toList();
    }

    /** The property group only, since the source is carried by the group rather than by each field. */
    static List<SearchFieldDataDto> propertyFields(List<SearchFieldDataByGroupDto> catalogue) {
        return catalogue
                .stream()
                .filter(group -> group.getFilterFieldSource() == FilterFieldSource.PROPERTY)
                .flatMap(group -> group.getSearchFieldData().stream())
                .toList();
    }
}
