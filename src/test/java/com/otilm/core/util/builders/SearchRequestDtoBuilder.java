package com.otilm.core.util.builders;

import com.otilm.api.model.client.certificate.SearchFilterRequestDto;
import com.otilm.api.model.client.certificate.SearchRequestDto;
import com.otilm.api.model.core.search.FilterConditionOperator;
import com.otilm.api.model.core.search.FilterFieldSource;

import java.io.Serializable;
import java.util.ArrayList;
import java.util.List;

/**
 * Test builder for {@link SearchRequestDto} with convenience methods for the common cases:
 * an unfiltered "give me everything" request and incremental filter accumulation.
 */
public final class SearchRequestDtoBuilder {

    private final List<SearchFilterRequestDto> filters = new ArrayList<>();
    private Integer itemsPerPage = 10;
    private Integer pageNumber = 1;

    public static SearchRequestDtoBuilder aSearchRequest() {
        return new SearchRequestDtoBuilder();
    }

    /**
     * An unfiltered request sized to return everything seeded in a test.
     */
    public static SearchRequestDto all() {
        return aSearchRequest().withItemsPerPage(1000).build();
    }

    public SearchRequestDtoBuilder withItemsPerPage(int itemsPerPage) {
        this.itemsPerPage = itemsPerPage;
        return this;
    }

    public SearchRequestDtoBuilder withPageNumber(int pageNumber) {
        this.pageNumber = pageNumber;
        return this;
    }

    public SearchRequestDtoBuilder withFilter(SearchFilterRequestDto filter) {
        this.filters.add(filter);
        return this;
    }

    public SearchRequestDtoBuilder withFilters(SearchFilterRequestDto... filters) {
        this.filters.addAll(List.of(filters));
        return this;
    }

    /**
     * Adds a single property filter; the most common filter shape in tests.
     */
    public SearchRequestDtoBuilder withPropertyFilter(String fieldIdentifier, FilterConditionOperator condition, Serializable value) {
        return withFilter(new SearchFilterRequestDto(FilterFieldSource.PROPERTY, fieldIdentifier, condition, value));
    }

    public SearchRequestDto build() {
        SearchRequestDto request = new SearchRequestDto();
        request.setFilters(List.copyOf(filters));
        request.setItemsPerPage(itemsPerPage);
        request.setPageNumber(pageNumber);
        return request;
    }
}
