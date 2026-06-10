package com.czertainly.core.util.builders;

import com.otilm.api.model.client.certificate.SearchFilterRequestDto;
import com.otilm.api.model.client.certificate.SearchRequestDto;

import java.util.List;

public class SearchRequestDtoBuilder {

    private List<SearchFilterRequestDto> filters = List.of();
    private int itemsPerPage = 10;
    private int pageNumber = 1;

    public static SearchRequestDtoBuilder aSearchRequest() {
        return new SearchRequestDtoBuilder();
    }

    public SearchRequestDtoBuilder withFilters(SearchFilterRequestDto... filters) {
        this.filters = List.of(filters);
        return this;
    }

    public SearchRequestDtoBuilder withItemsPerPage(int itemsPerPage) {
        this.itemsPerPage = itemsPerPage;
        return this;
    }

    public SearchRequestDtoBuilder withPageNumber(int pageNumber) {
        this.pageNumber = pageNumber;
        return this;
    }

    public SearchRequestDto build() {
        SearchRequestDto dto = new SearchRequestDto();
        dto.setFilters(filters.isEmpty() ? null : filters);
        dto.setItemsPerPage(itemsPerPage);
        dto.setPageNumber(pageNumber);
        return dto;
    }
}
