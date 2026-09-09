package com.otilm.core.util;

import com.otilm.api.exception.ValidationError;
import com.otilm.api.exception.ValidationException;
import com.otilm.api.model.client.certificate.SearchRequestDto;
import com.otilm.api.model.core.auth.Resource;
import com.otilm.api.model.core.scheduler.PaginationRequestDto;

import java.util.ArrayList;

public class RequestValidatorHelper {

    private static final Integer DEFAULT_ITEMS_PER_PAGE = 10;

    /**
     * As below, and refuses a sort the listing of this resource would not apply.
     *
     * <p>
     * The catalogue reports every field of an unwired listing as {@code sortable:false}, but that flag is a hint on a
     * response the caller is free to ignore. Answering such a request with the default order and no explanation is the
     * failure the flag exists to prevent, so it is refused instead - the same answer
     * {@code CryptographicAssetServiceImpl} has always given.
     */
    public static void revalidateSearchRequestDto(final SearchRequestDto dto, final Resource resource) {
        if (dto.getSort() != null && !SearchHelper.listingAppliesSort(resource)) {
            throw new ValidationException(ValidationError
                    .create("Sorting is not supported for the %s listing.".formatted(resource.getLabel())));
        }
        revalidateSearchRequestDto(dto);
    }

    public static void revalidateSearchRequestDto(final SearchRequestDto dto) {
        if (dto.getFilters() == null) {
            dto.setFilters(new ArrayList<>());
        }
        if (dto.getItemsPerPage() == null) {
            dto.setItemsPerPage(DEFAULT_ITEMS_PER_PAGE);
        }
        if (dto.getPageNumber() == null) {
            dto.setPageNumber(1);
        }
    }

    public static void revalidatePaginationRequestDto(final PaginationRequestDto dto) {
        if (dto.getItemsPerPage() == null) {
            dto.setItemsPerPage(DEFAULT_ITEMS_PER_PAGE);
        }
        if (dto.getPageNumber() == null) {
            dto.setPageNumber(1);
        }
    }

}
