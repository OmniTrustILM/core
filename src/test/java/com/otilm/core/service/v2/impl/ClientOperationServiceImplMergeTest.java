package com.otilm.core.service.v2.impl;

import com.otilm.api.model.common.attribute.v3.DataAttributeV3;
import com.otilm.api.model.common.attribute.v3.mapping.FieldMapping;
import com.otilm.api.model.common.attribute.v3.mapping.FieldType;
import com.otilm.api.model.common.attribute.v3.mapping.RdnMappedField;
import com.otilm.core.attribute.CsrAttributes;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

class ClientOperationServiceImplMergeTest {

    @Test
    void retainsUnmappedConnectorDefinition() {
        // given a connector definition without a fieldMapping (a connector-specific field)
        List<DataAttributeV3> defaults = CsrAttributes.csrAttributesAsDataAttributesV3();
        DataAttributeV3 unmapped = dataAttribute("connector-custom", null);

        // when
        List<DataAttributeV3> merged =
                ClientOperationServiceImpl.mergeIssuanceDefinitions(defaults, List.of(unmapped), Map.of());

        // then the unmapped connector definition survives the merge
        assertThat(merged).extracting(DataAttributeV3::getName).contains("connector-custom");
        assertThat(merged).containsAll(defaults);
    }

    @Test
    void connectorDefinitionOverridesDefaultClaimingSameRdn() {
        // given a connector definition that claims the same RDN as the default Common Name attribute
        List<DataAttributeV3> defaults = CsrAttributes.csrAttributesAsDataAttributesV3();
        DataAttributeV3 defaultCommonName = defaults.get(0);
        String commonNameRdn = ((RdnMappedField) defaultCommonName.getFieldMapping().getFields().get(0)).getRdn();
        DataAttributeV3 connectorCommonName = dataAttribute("connector-cn", rdnMapping(commonNameRdn));

        // when
        List<DataAttributeV3> merged =
                ClientOperationServiceImpl.mergeIssuanceDefinitions(defaults, List.of(connectorCommonName), Map.of());

        // then the connector definition replaces the overlapping default; other defaults remain
        assertThat(merged).contains(connectorCommonName).doesNotContain(defaultCommonName);
        assertThat(merged).hasSize(defaults.size());
    }

    private static DataAttributeV3 dataAttribute(String name, FieldMapping fieldMapping) {
        DataAttributeV3 attr = new DataAttributeV3();
        attr.setUuid(name);
        attr.setName(name);
        attr.setFieldMapping(fieldMapping);
        return attr;
    }

    private static FieldMapping rdnMapping(String rdnCode) {
        RdnMappedField field = new RdnMappedField();
        field.setFieldType(FieldType.RDN);
        field.setRdn(rdnCode);

        FieldMapping fm = new FieldMapping();
        fm.setFields(List.of(field));
        return fm;
    }
}
