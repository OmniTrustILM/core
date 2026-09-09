package com.otilm.core.dao.repository;

import com.otilm.api.model.client.certificate.SearchSortRequestDto;
import com.otilm.api.model.core.auth.Resource;
import com.otilm.api.model.core.search.FilterFieldSource;
import com.otilm.api.model.core.search.SortDirection;
import com.otilm.core.attribute.engine.AttributeEngine.CustomAttributeContentFilter;
import java.util.function.Supplier;

/**
 * Ordering a caller asked for, addressed the way a filter addresses a field: a source plus an identifier that is unique
 * only within that source. Carried instead of a ready-made {@code Order} lambda so the repository can decide how the
 * ordering interacts with the rest of the query it builds - the {@code SELECT DISTINCT} it emits, and the tie-break it
 * appends to keep paging stable.
 *
 * <p>
 * An attribute-sourced sort additionally carries the resource whose catalogue it was resolved against and the caller's
 * custom-attribute content permissions. Neither can be recovered from the entity root: a resource without a
 * {@code ResourceToClass} entry maps to no resource at all, and permissions live on the request rather than on the
 * query. Both are supplied by {@code ListingSortResolver}, which is the only thing that may build one; a specification
 * that reaches the attribute sort key without them is refused rather than run unauthorized.
 *
 * @param resource the resource the listing selects, or {@code null} for a specification built without one
 * @param attributeContentFilterSource the caller's custom-attribute permissions, or {@code null} when no attribute sort
 * was resolved. A supplier so that the listing's filter, sort and projection share one resolution.
 */
public record SortSpecification(FilterFieldSource fieldSource, String fieldIdentifier, SortDirection direction,
        Resource resource, Supplier<CustomAttributeContentFilter> attributeContentFilterSource) {

    public SortSpecification(FilterFieldSource fieldSource, String fieldIdentifier, SortDirection direction) {
        this(fieldSource, fieldIdentifier, direction, null, null);
    }

    public static SortSpecification from(SearchSortRequestDto dto) {
        return dto == null
                ? null
                : new SortSpecification(dto.getFieldSource(), dto.getFieldIdentifier(), dto.getDirection());
    }
}
