package com.otilm.core.certificate.request.valuesource;

import com.otilm.api.model.common.attribute.v3.mapping.SourceParam;
import com.otilm.api.model.common.attribute.v3.mapping.ValueSourceType;

import java.util.List;

/**
 * SPI for resolving the selectable options of a Core-side value-source binding.
 *
 * <p>A value-source binding ({@link com.otilm.core.dao.entity.RaProfileValueSourceBinding}) attaches a
 * {@link ValueSourceType} (and an optional {@code collectionRef} + cascading {@link SourceParam} filters) onto a
 * request-attribute definition. At request-rendering time the platform must turn that binding into a concrete set of
 * options the operator can pick from (e.g. a list of CMDB servers, a static enumeration). This interface is the
 * extension point: each provider serves one {@link ValueSourceType} and resolves its options.
 */
public interface CollectionValueSourceProvider {

    /**
     * @return {@code true} if this provider resolves options for the given value-source type.
     */
    boolean supports(ValueSourceType valueSourceType);

    /**
     * Resolves the selectable options for a bound value source.
     *
     * @param collectionRef reference to a registered collection/source (may be {@code null} for self-contained sources)
     * @param params        cascading dependency filters scoping the source by other attributes' values (never {@code null})
     * @return the ordered, selectable options
     */
    List<CollectionValueOption> resolveOptions(String collectionRef, List<SourceParam> params);

    /**
     * A single selectable option: the stored {@code value} and the human-friendly {@code label} shown to the operator.
     */
    record CollectionValueOption(String value, String label) {
    }
}
