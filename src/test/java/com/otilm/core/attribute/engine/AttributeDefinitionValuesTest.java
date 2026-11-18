package com.otilm.core.attribute.engine;

import com.otilm.api.model.common.attribute.common.callback.AttributeCallback;
import com.otilm.api.model.common.attribute.common.callback.AttributeCallbackMapping;
import com.otilm.api.model.common.attribute.common.callback.AttributeValueTarget;
import com.otilm.api.model.common.attribute.common.content.AttributeContentType;
import com.otilm.api.model.common.attribute.common.properties.DataAttributeProperties;
import com.otilm.api.model.common.attribute.v2.DataAttributeV2;
import com.otilm.api.model.common.attribute.v2.content.BaseAttributeContentV2;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

class AttributeDefinitionValuesTest {

    @Test
    void reportsSameValue_whenOnlyTheOrderOfObjectKeysDiffers() {
        // given
        var storedOrder = new LinkedHashMap<String, Object>();
        storedOrder.put("oid", "2.5.29.17");
        storedOrder.put("critical", false);
        var sentOrder = new LinkedHashMap<String, Object>();
        sentOrder.put("critical", false);
        sentOrder.put("oid", "2.5.29.17");

        // when
        boolean same = AttributeDefinitionValues
                .sameValue(anAttributeWithObjectContent(storedOrder), anAttributeWithObjectContent(sentOrder));

        // then
        assertThat(same).isTrue();
    }

    @Test
    void reportsSameValue_whenCallbackMappingsAndTheirTargetsComeInAnotherOrder() {
        // given
        var storedOrder = anAttributeWithCallback(
                aMapping("algorithm", AttributeValueTarget.PATH_VARIABLE, AttributeValueTarget.REQUEST_PARAMETER),
                aMapping("curve", AttributeValueTarget.BODY));
        var sentOrder = anAttributeWithCallback(aMapping("curve", AttributeValueTarget.BODY),
                aMapping("algorithm", AttributeValueTarget.REQUEST_PARAMETER, AttributeValueTarget.PATH_VARIABLE));

        // when
        boolean same = AttributeDefinitionValues.sameValue(storedOrder, sentOrder);

        // then
        assertThat(same).isTrue();
    }

    @Test
    void reportsDifferentValue_whenACallbackMappingDiffers() {
        // given
        var stored = anAttributeWithCallback(aMapping("algorithm", AttributeValueTarget.PATH_VARIABLE));
        var changedTarget = anAttributeWithCallback(aMapping("algorithm", AttributeValueTarget.REQUEST_PARAMETER));

        // when
        boolean same = AttributeDefinitionValues.sameValue(stored, changedTarget);

        // then
        assertThat(same).isFalse();
    }

    @Test
    void reportsDifferentValue_whenADescriptionDiffers() {
        // given
        var stored = anAttribute();
        var changed = anAttribute();
        changed.setDescription("changed");

        // when
        boolean same = AttributeDefinitionValues.sameValue(stored, changed);

        // then
        assertThat(same).isFalse();
    }

    @Test
    void reportsDifferentValue_whenContentIsMissingOnOneSideAndEmptyOnTheOther() {
        // given
        var withoutContent = anAttribute();
        var withEmptyContent = anAttribute();
        withEmptyContent.setContent(List.of());

        // when
        boolean same = AttributeDefinitionValues.sameValue(withoutContent, withEmptyContent);

        // then
        assertThat(same).isFalse();
    }

    // ── Helpers ───────────────────────────────────────────────────────────────

    private static DataAttributeV2 anAttribute() {
        DataAttributeV2 attribute = new DataAttributeV2();
        attribute.setUuid("7e7a3b8c-1d2e-4f50-8a9b-0c1d2e3f4a5b");
        attribute.setName("extension");
        attribute.setDescription("Extension");
        attribute.setContentType(AttributeContentType.OBJECT);
        DataAttributeProperties properties = new DataAttributeProperties();
        properties.setLabel("Extension");
        attribute.setProperties(properties);
        return attribute;
    }

    private static DataAttributeV2 anAttributeWithObjectContent(LinkedHashMap<String, Object> data) {
        DataAttributeV2 attribute = anAttribute();
        BaseAttributeContentV2<LinkedHashMap<String, Object>> content = new BaseAttributeContentV2<>();
        content.setReference("subjectAltName");
        content.setData(data);
        attribute.setContent(List.of(content));
        return attribute;
    }

    /** Builds the callback's sets in the given order, as a deserialized copy may iterate them. */
    private static DataAttributeV2 anAttributeWithCallback(AttributeCallbackMapping... mappings) {
        DataAttributeV2 attribute = anAttribute();
        AttributeCallback callback = new AttributeCallback();
        callback.setCallbackContext("/v1/keyspec/{algorithm}");
        callback.setCallbackMethod("GET");
        callback.setMappings(new LinkedHashSet<>(List.of(mappings)));
        attribute.setAttributeCallback(callback);
        return attribute;
    }

    private static AttributeCallbackMapping aMapping(String to, AttributeValueTarget... targets) {
        return new AttributeCallbackMapping("data_" + to, to, new LinkedHashSet<>(List.of(targets)));
    }
}
