package com.czertainly.core.mapper.workflows;

import com.czertainly.api.model.common.PaginationResponseDto;
import org.springframework.data.domain.Page;

import java.util.List;

public class PaginationResponseMapper {

    private PaginationResponseMapper() {
    }

    /**
     * Builds a paginated response from a Spring {@link Page} (repositories that return Page directly).
     */
    public static <T> PaginationResponseDto<T> toDto(Page<?> page, List<T> items) {
        return toDto(items, page.getNumber() + 1, page.getSize(), page.getTotalElements());
    }

    /**
     * Builds a paginated response from flat parameters (e.g. SecurityFilterRepository which returns
     * a List + a separate count instead of a Page).
     */
    public static <T> PaginationResponseDto<T> toDto(List<T> items, int pageNumber, int itemsPerPage, long totalItems) {
        PaginationResponseDto<T> dto = new PaginationResponseDto<>();
        dto.setItems(items);
        dto.setPageNumber(pageNumber);
        dto.setItemsPerPage(itemsPerPage);
        dto.setTotalItems(totalItems);
        dto.setTotalPages(itemsPerPage > 0 ? (int) Math.ceil((double) totalItems / itemsPerPage) : 0);
        return dto;
    }
}
