package com.otilm.core.certificate.request;

import com.otilm.api.model.common.attribute.common.BaseAttribute;
import com.otilm.api.model.common.attribute.common.content.AttributeContentType;
import com.otilm.api.model.common.attribute.v3.DataAttributeV3;
import com.otilm.api.model.common.attribute.v3.mapping.SourceParam;
import com.otilm.api.model.common.attribute.v3.mapping.ValueSourceType;
import com.otilm.api.model.common.attribute.common.properties.DataAttributeProperties;
import com.otilm.api.model.core.raprofile.AttributeSetMergeMode;
import com.otilm.core.certificate.request.RequestAttributeSetResolver.ValueSourceBindingSpec;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

class RequestAttributeSetResolverTest {

    private static DataAttributeV3 def(String uuid, String name) {
        DataAttributeV3 attribute = new DataAttributeV3();
        attribute.setUuid(uuid);
        attribute.setName(name);
        attribute.setContentType(AttributeContentType.STRING);
        DataAttributeProperties properties = new DataAttributeProperties();
        properties.setLabel(name);
        attribute.setProperties(properties);
        return attribute;
    }

    @Nested
    class Merge {

        @Test
        void staticOnlyIgnoresConnectorSet() {
            // given / when
            List<BaseAttribute> result = RequestAttributeSetResolver.merge(
                    List.of(def("u1", "a")), List.of(def("u2", "b")), AttributeSetMergeMode.STATIC_ONLY);

            // then
            assertThat(result).extracting(BaseAttribute::getName).containsExactly("a");
        }

        @Test
        void connectorOnlyIgnoresStaticSet() {
            // given / when
            List<BaseAttribute> result = RequestAttributeSetResolver.merge(
                    List.of(def("u1", "a")), List.of(def("u2", "b")), AttributeSetMergeMode.CONNECTOR_ONLY);

            // then
            assertThat(result).extracting(BaseAttribute::getName).containsExactly("b");
        }

        @Test
        void mergeUnionsConnectorWinsOnUuidConflict() {
            // given: same UUID in both sets — connector definition wins, static one is dropped
            DataAttributeV3 staticConflict = def("shared", "static-name");
            DataAttributeV3 connectorConflict = def("shared", "connector-name");
            DataAttributeV3 staticOnly = def("s-only", "static-only");
            DataAttributeV3 connectorOnly = def("c-only", "connector-only");

            // when
            List<BaseAttribute> result = RequestAttributeSetResolver.merge(
                    List.of(staticConflict, staticOnly),
                    List.of(connectorConflict, connectorOnly),
                    AttributeSetMergeMode.MERGE);

            // then: connector definitions first (connector order), then static-only definitions
            assertThat(result).extracting(BaseAttribute::getName)
                    .containsExactly("connector-name", "connector-only", "static-only");
        }

        @Test
        void mergeUsesNameFallbackWhenUuidNull() {
            // given: both sets carry a definition with a null UUID and the same name
            DataAttributeV3 staticByName = def(null, "shared-name");
            DataAttributeV3 connectorByName = def(null, "shared-name");

            // when
            List<BaseAttribute> result = RequestAttributeSetResolver.merge(
                    List.of(staticByName), List.of(connectorByName), AttributeSetMergeMode.MERGE);

            // then: de-duplicated by the name fallback key; connector wins
            assertThat(result).hasSize(1);
            assertThat(result.get(0)).isSameAs(connectorByName);
        }

        @Test
        void mergeTreatsBlankUuidAsNameKey() {
            // given: a blank (not null) UUID must still fall back to the name key
            DataAttributeV3 staticBlank = def("  ", "shared-name");
            DataAttributeV3 connectorBlank = def("", "shared-name");

            // when
            List<BaseAttribute> result = RequestAttributeSetResolver.merge(
                    List.of(staticBlank), List.of(connectorBlank), AttributeSetMergeMode.MERGE);

            // then
            assertThat(result).hasSize(1);
            assertThat(result.get(0)).isSameAs(connectorBlank);
        }

        @Test
        void nullModeDefaultsToMerge() {
            // given / when
            List<BaseAttribute> result = RequestAttributeSetResolver.merge(
                    List.of(def("u1", "a")), List.of(def("u2", "b")), null);

            // then
            assertThat(result).hasSize(2);
        }

        @Test
        void nullSetsTreatedAsEmpty() {
            assertThat(RequestAttributeSetResolver.merge(null, null, AttributeSetMergeMode.MERGE)).isEmpty();
            assertThat(RequestAttributeSetResolver.merge(List.of(def("u1", "a")), null, AttributeSetMergeMode.MERGE)).hasSize(1);
            assertThat(RequestAttributeSetResolver.merge(null, List.of(def("u2", "b")), AttributeSetMergeMode.MERGE)).hasSize(1);
        }
    }

    @Nested
    class EffectiveMode {

        @Test
        void nullResolvesToMerge() {
            assertThat(RequestAttributeSetResolver.effectiveMode(null)).isEqualTo(AttributeSetMergeMode.MERGE);
        }

        @Test
        void nonNullIsReturnedUnchanged() {
            assertThat(RequestAttributeSetResolver.effectiveMode(AttributeSetMergeMode.STATIC_ONLY))
                    .isEqualTo(AttributeSetMergeMode.STATIC_ONLY);
            assertThat(RequestAttributeSetResolver.effectiveMode(AttributeSetMergeMode.CONNECTOR_ONLY))
                    .isEqualTo(AttributeSetMergeMode.CONNECTOR_ONLY);
        }
    }

    @Nested
    class ApplyValueSourceBindings {

        @Test
        void bindingByUuidSetsValueSource() {
            // given
            DataAttributeV3 connector = def("u1", "server");
            ValueSourceBindingSpec binding = new ValueSourceBindingSpec(
                    "u1", null, ValueSourceType.STATIC_LIST, "cmdb.servers", List.of());

            // when
            List<BaseAttribute> result = RequestAttributeSetResolver.applyValueSourceBindings(List.of(connector), List.of(binding));

            // then
            DataAttributeV3 out = (DataAttributeV3) result.get(0);
            assertThat(out.getValueSource()).isNotNull();
            assertThat(out.getValueSource().getKind()).isEqualTo(ValueSourceType.STATIC_LIST);
        }

        @Test
        void bindingUsesNameFallbackWhenUuidDoesNotMatch() {
            // given: the connector rotated the attribute UUID, so the binding's UUID no longer matches;
            // it must still bind via the attribute name fallback rather than silently dropping the value source
            DataAttributeV3 connector = def("changed-uuid", "server");
            ValueSourceBindingSpec binding = new ValueSourceBindingSpec(
                    "old-uuid", "server", ValueSourceType.CONNECTOR_CALLBACK, null, List.of());

            // when
            List<BaseAttribute> result = RequestAttributeSetResolver.applyValueSourceBindings(List.of(connector), List.of(binding));

            // then
            DataAttributeV3 out = (DataAttributeV3) result.get(0);
            assertThat(out.getValueSource()).isNotNull();
            assertThat(out.getValueSource().getKind()).isEqualTo(ValueSourceType.CONNECTOR_CALLBACK);
        }

        @Test
        void bindingCarriesSourceParams() {
            // given
            DataAttributeV3 connector = def("u1", "server");
            SourceParam param = new SourceParam();
            param.setAttributeName("datacenter");
            ValueSourceBindingSpec binding = new ValueSourceBindingSpec(
                    "u1", null, ValueSourceType.STATIC_LIST, null, List.of(param));

            // when
            List<BaseAttribute> result = RequestAttributeSetResolver.applyValueSourceBindings(List.of(connector), List.of(binding));

            // then
            DataAttributeV3 out = (DataAttributeV3) result.get(0);
            assertThat(out.getValueSource().getParams()).extracting(SourceParam::getAttributeName).containsExactly("datacenter");
        }

        @Test
        void noBindingLeavesDefinitionUntouched() {
            // given / when
            DataAttributeV3 connector = def("u1", "server");
            List<BaseAttribute> result = RequestAttributeSetResolver.applyValueSourceBindings(List.of(connector), List.of());

            // then
            assertThat(((DataAttributeV3) result.get(0)).getValueSource()).isNull();
        }

        @Test
        void unmatchedBindingLeavesDefinitionUntouched() {
            // given: a binding that matches neither the UUID nor the name
            DataAttributeV3 connector = def("u1", "server");
            ValueSourceBindingSpec mismatch = new ValueSourceBindingSpec(
                    "other", "other", ValueSourceType.STATIC_LIST, "x", List.of());

            // when
            List<BaseAttribute> result = RequestAttributeSetResolver.applyValueSourceBindings(List.of(connector), List.of(mismatch));

            // then
            assertThat(((DataAttributeV3) result.get(0)).getValueSource()).isNull();
        }

        @Test
        void nullDefinitionsYieldEmptyList() {
            assertThat(RequestAttributeSetResolver.applyValueSourceBindings(null, List.of())).isEmpty();
        }

        @Test
        void nullBindingsLeaveDefinitionsUntouched() {
            // given / when
            DataAttributeV3 connector = def("u1", "server");
            List<BaseAttribute> result = RequestAttributeSetResolver.applyValueSourceBindings(List.of(connector), null);

            // then
            assertThat(((DataAttributeV3) result.get(0)).getValueSource()).isNull();
        }
    }
}
