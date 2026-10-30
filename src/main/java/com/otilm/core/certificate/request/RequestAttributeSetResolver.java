package com.otilm.core.certificate.request;

import com.otilm.api.model.common.attribute.common.BaseAttribute;
import com.otilm.api.model.common.attribute.v3.DataAttributeV3;
import com.otilm.api.model.common.attribute.v3.mapping.SourceParam;
import com.otilm.api.model.common.attribute.v3.mapping.ValueSource;
import com.otilm.api.model.common.attribute.v3.mapping.ValueSourceType;
import com.otilm.api.model.core.raprofile.AttributeSetMergeMode;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Optional;
import java.util.Set;

/**
 * Pure resolution kernel for request-attribute sets.
 *
 * <p>
 * Combines the RA-Profile static set with the connector-supplied dynamic set per a merge mode, and applies Core-side
 * {@code valueSource} bindings onto connector (or static) definitions.
 */
public final class RequestAttributeSetResolver {

    private RequestAttributeSetResolver() {
    }

    /**
     * Resolves a possibly-{@code null} stored merge mode to its effective value.
     *
     * @param mode the per-RA-Profile merge mode as stored (may be {@code null})
     * @return {@code mode} when non-null, otherwise {@link AttributeSetMergeMode#STATIC_ONLY}
     */
    public static AttributeSetMergeMode effectiveMode(AttributeSetMergeMode mode) {
        return mode == null ? AttributeSetMergeMode.STATIC_ONLY : mode;
    }

    /**
     * @param staticSet the RA-Profile static definitions (may be {@code null})
     * @param connectorSet the connector-supplied dynamic definitions (may be {@code null})
     * @param mode the per-RA-Profile merge mode; {@code null} is treated as {@link AttributeSetMergeMode#STATIC_ONLY}
     * @return the resolved, ordered set
     */
    public static List<BaseAttribute> merge(List<? extends BaseAttribute> staticSet,
            List<? extends BaseAttribute> connectorSet, AttributeSetMergeMode mode) {
        List<? extends BaseAttribute> staticDefs = staticSet == null ? List.of() : staticSet;
        List<? extends BaseAttribute> connectorDefs = connectorSet == null ? List.of() : connectorSet;
        AttributeSetMergeMode effective = effectiveMode(mode);

        return switch (effective) {
            case STATIC_ONLY -> new ArrayList<>(staticDefs);
            case CONNECTOR_ONLY -> new ArrayList<>(connectorDefs);
            case MERGE -> mergeUnion(staticDefs, connectorDefs);
        };
    }

    private static List<BaseAttribute> mergeUnion(List<? extends BaseAttribute> staticDefs,
            List<? extends BaseAttribute> connectorDefs) {
        // Connector definitions first, in their order; they win any conflict. A definition is claimed by either key:
        // the attribute engine registers definitions under their name (a name-keyed map), so two definitions sharing
        // a name cannot both survive the merge even when their UUIDs differ — and the platform seed pins UUIDs the
        // connector will not reuse, making that the ordinary collision rather than an exotic one.
        List<BaseAttribute> merged = new ArrayList<>();
        Set<String> claimedUuids = new HashSet<>();
        Set<String> claimedNames = new HashSet<>();
        for (BaseAttribute def : connectorDefs) {
            addUnlessClaimed(def, merged, claimedUuids, claimedNames);
        }
        for (BaseAttribute def : staticDefs) {
            addUnlessClaimed(def, merged, claimedUuids, claimedNames);
        }
        return merged;
    }

    private static void addUnlessClaimed(BaseAttribute def, List<BaseAttribute> merged, Set<String> claimedUuids,
            Set<String> claimedNames) {
        String uuid = blankToNull(def.getUuid());
        String name = blankToNull(def.getName());
        if ((uuid != null && claimedUuids.contains(uuid)) || (name != null && claimedNames.contains(name))) {
            return;
        }
        if (uuid != null) {
            claimedUuids.add(uuid);
        }
        if (name != null) {
            claimedNames.add(name);
        }
        merged.add(def);
    }

    private static String blankToNull(String value) {
        return value == null || value.isBlank() ? null : value;
    }

    // ---- value-source binding -------------------------------------------------------

    /**
     * A Core-side value-source binding, decoupled from the {@code RaProfileValueSourceBinding} entity so the kernel
     * stays Spring/JPA-free. {@code attributeUuid} is the primary key; {@code attributeName} is the fallback.
     */
    public record ValueSourceBindingSpec(String attributeUuid, String attributeName, ValueSourceType valueSourceType,
            List<SourceParam> params) {
    }

    /**
     * Applies Core-side value-source bindings onto the resolved definitions. A binding binds to a definition by UUID,
     * falling back to name. Only {@link DataAttributeV3} definitions can carry a {@code valueSource}; others are passed
     * through untouched. Definitions are mutated in place and returned.
     *
     * <p>
     * A matched binding <em>overrides</em> any {@code valueSource} a connector definition already carries.
     */
    public static List<BaseAttribute> applyValueSourceBindings(List<? extends BaseAttribute> definitions,
            List<ValueSourceBindingSpec> bindings) {
        if (definitions == null) {
            return new ArrayList<>();
        }
        List<ValueSourceBindingSpec> bindingList = bindings == null ? List.of() : bindings;
        for (BaseAttribute def : definitions) {
            if (!(def instanceof DataAttributeV3 v3)) {
                continue;
            }
            findValueSourceBinding(v3, bindingList).ifPresent(binding -> v3.setValueSource(toValueSource(binding)));
        }
        return new ArrayList<>(definitions);
    }

    private static Optional<ValueSourceBindingSpec> findValueSourceBinding(DataAttributeV3 def,
            List<ValueSourceBindingSpec> bindings) {
        for (ValueSourceBindingSpec binding : bindings) {
            boolean uuidMatch = binding.attributeUuid() != null && binding.attributeUuid().equals(def.getUuid());
            // Name is a deliberate fallback that fires even when the binding has a UUID, so a binding survives the
            // connector rotating the attribute's UUID.
            boolean nameMatch = binding.attributeName() != null && binding.attributeName().equals(def.getName());
            if (uuidMatch || nameMatch) {
                return Optional.of(binding);
            }
        }
        return Optional.empty();
    }

    private static ValueSource toValueSource(ValueSourceBindingSpec binding) {
        ValueSource valueSource = new ValueSource();
        valueSource.setKind(binding.valueSourceType());
        // SourceParam dependency filters are stored verbatim and not yet resolved here: cascading
        // resolution (evaluating one source's value against another's filter) is intentionally deferred.
        valueSource.setParams(binding.params() == null || binding.params().isEmpty() ? null : binding.params());
        return valueSource;
    }
}
