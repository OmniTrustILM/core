package com.otilm.core.attribute.engine;

import com.otilm.api.exception.ValidationError;
import com.otilm.api.exception.ValidationException;
import com.otilm.api.model.client.certificate.SearchSortRequestDto;
import com.otilm.api.model.core.auth.Resource;
import com.otilm.api.model.core.search.FilterFieldSource;
import com.otilm.api.model.core.search.SearchFieldDataDto;
import com.otilm.core.attribute.engine.AttributeEngine.CustomAttributeContentFilter;
import com.otilm.core.dao.repository.SortSpecification;
import java.util.Objects;
import java.util.function.Supplier;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Component;

/**
 * The sort a listing request carries, resolved against the resource whose listing will apply it.
 *
 * <p>
 * A property sort names a {@code FilterField}, which {@code SortOrderBuilder} resolves and refuses when the catalogue
 * withholds it. An attribute sort names a definition instead, and there is no enum to refuse it against - so it is
 * checked here, against the same published catalogue the client read the {@code sortable} flag from. Without this a
 * request could order by exactly the fields the catalogue reports as {@code sortable:false}: secret and code-block
 * content, encrypted content, and definitions marked not visible.
 *
 * <p>
 * The resolved specification also carries the caller's custom-attribute permissions into the query that reads the
 * value. The projection path applies them ({@code AttributeColumnProjector}), and an ordering that did not would let a
 * caller compare the values of an attribute the same response blanks - a comparative oracle over content they are
 * denied.
 */
@Component
@RequiredArgsConstructor
public class ListingSortResolver {

    private final AttributeEngine attributeEngine;

    /**
     * The specification a listing hands the repository, or {@code null} when the request named no sort.
     *
     * @param resource the resource the listing selects, which is what the identifier is resolved against
     * @param contentFilterSource the caller's custom-attribute permissions, carried onto the specification so the
     * ordering reads the same resolution the listing's filter and projection do
     */
    public SortSpecification resolve(final Resource resource, final SearchSortRequestDto sort,
            final Supplier<CustomAttributeContentFilter> contentFilterSource) {
        if (sort == null) {
            return null;
        }
        final FilterFieldSource source = sort.getFieldSource();
        if (source == null || source.getAttributeType() == null) {
            return new SortSpecification(source, sort.getFieldIdentifier(), sort.getDirection(), resource, null);
        }
        requireSortableAttributeField(resource, source, sort.getFieldIdentifier());
        return new SortSpecification(source, sort.getFieldIdentifier(), sort.getDirection(), resource,
                contentFilterSource);
    }

    /**
     * Refuses an attribute field the resource's catalogue does not publish as sortable, with the message the property
     * path uses for the same refusal. Read from the catalogue rather than from a copy of its rules, so the flag the
     * client was given and the answer it gets back cannot disagree.
     */
    private void requireSortableAttributeField(final Resource resource, final FilterFieldSource source,
            final String fieldIdentifier) {
        final SearchFieldDataDto field = attributeEngine
                .getResourceSearchableFields(resource, false)
                .stream()
                .filter(group -> group.getFilterFieldSource() == source)
                .flatMap(group -> group.getSearchFieldData().stream())
                .filter(item -> Objects.equals(item.getFieldIdentifier(), fieldIdentifier))
                .findFirst()
                .orElseThrow(() -> new ValidationException(
                        ValidationError.create("Unknown sort field identifier %s.".formatted(fieldIdentifier))));

        if (!Boolean.TRUE.equals(field.getSortable())) {
            throw new ValidationException(ValidationError
                    .create("Field %s cannot be used to order this listing.".formatted(fieldIdentifier)));
        }
    }
}
