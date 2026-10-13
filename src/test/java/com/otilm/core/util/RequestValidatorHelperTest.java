package com.otilm.core.util;

import com.otilm.api.exception.ValidationException;
import com.otilm.api.model.client.certificate.SearchRequestDto;
import com.otilm.api.model.core.scheduler.PaginationRequestDto;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class RequestValidatorHelperTest {

    private static SearchRequestDto searchRequest(Integer itemsPerPage, Integer pageNumber) {
        SearchRequestDto dto = new SearchRequestDto();
        dto.setItemsPerPage(itemsPerPage);
        dto.setPageNumber(pageNumber);
        return dto;
    }

    private static PaginationRequestDto paginationRequest(Integer itemsPerPage, Integer pageNumber) {
        PaginationRequestDto dto = new PaginationRequestDto();
        dto.setItemsPerPage(itemsPerPage);
        dto.setPageNumber(pageNumber);
        return dto;
    }

    @Test
    void searchRequestAboveTheDocumentedMaximumIsRefusedNamingTheLimit() {
        SearchRequestDto dto = searchRequest(1001, 1);

        assertThatThrownBy(() -> RequestValidatorHelper.revalidateSearchRequestDto(dto))
                .isInstanceOf(ValidationException.class)
                .hasMessageContaining("Items per page must be at most 1000, but was 1001");
    }

    @Test
    void paginationRequestAboveTheDocumentedMaximumIsRefusedNamingTheLimit() {
        PaginationRequestDto dto = paginationRequest(1001, 1);

        assertThatThrownBy(() -> RequestValidatorHelper.revalidatePaginationRequestDto(dto))
                .isInstanceOf(ValidationException.class)
                .hasMessageContaining("Items per page must be at most 1000, but was 1001");
    }

    @ParameterizedTest
    @ValueSource(ints = {1, 1000})
    void pageSizesWithinTheDocumentedRangeAreAccepted(int itemsPerPage) {
        SearchRequestDto search = searchRequest(itemsPerPage, 1);
        PaginationRequestDto pagination = paginationRequest(itemsPerPage, 1);

        RequestValidatorHelper.revalidateSearchRequestDto(search);
        RequestValidatorHelper.revalidatePaginationRequestDto(pagination);

        assertThat(search.getItemsPerPage()).isEqualTo(itemsPerPage);
        assertThat(pagination.getItemsPerPage()).isEqualTo(itemsPerPage);
    }

    @ParameterizedTest
    @ValueSource(ints = {0, -1})
    void pageSizeBelowOneIsRefused(int itemsPerPage) {
        SearchRequestDto dto = searchRequest(itemsPerPage, 1);

        assertThatThrownBy(() -> RequestValidatorHelper.revalidateSearchRequestDto(dto))
                .isInstanceOf(ValidationException.class)
                .hasMessageContaining("Items per page must be at least 1");
    }

    @Test
    void pageNumberBelowOneIsRefused() {
        SearchRequestDto dto = searchRequest(10, 0);

        assertThatThrownBy(() -> RequestValidatorHelper.revalidateSearchRequestDto(dto))
                .isInstanceOf(ValidationException.class)
                .hasMessageContaining("Page number must be at least 1");
    }

    @Test
    void anOffsetBeyondTheIntRangeIsRefused() {
        SearchRequestDto dto = searchRequest(1000, 2147485);

        assertThatThrownBy(() -> RequestValidatorHelper.revalidateSearchRequestDto(dto))
                .isInstanceOf(ValidationException.class)
                .hasMessageContaining("exceeds the addressable offset");
    }

    @Test
    void missingPagingFallsBackToTheDefaults() {
        SearchRequestDto dto = searchRequest(null, null);

        RequestValidatorHelper.revalidateSearchRequestDto(dto);

        assertThat(dto.getItemsPerPage()).isEqualTo(10);
        assertThat(dto.getPageNumber()).isEqualTo(1);
        assertThat(dto.getFilters()).isEmpty();
    }
}
