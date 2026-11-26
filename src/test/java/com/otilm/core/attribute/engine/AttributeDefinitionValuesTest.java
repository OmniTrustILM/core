package com.otilm.core.attribute.engine;

import com.otilm.api.model.common.attribute.common.callback.AttributeCallback;
import com.otilm.api.model.common.attribute.common.callback.AttributeCallbackMapping;
import com.otilm.api.model.common.attribute.common.callback.AttributeValueTarget;
import com.otilm.api.model.common.attribute.common.content.AttributeContentType;
import com.otilm.api.model.common.attribute.common.properties.DataAttributeProperties;
import com.otilm.api.model.common.attribute.v2.DataAttributeV2;
import com.otilm.api.model.common.attribute.v2.content.BaseAttributeContentV2;
import java.io.Serializable;
import java.time.LocalDate;
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
                .sameValue(createAttributeWithContent(storedOrder), createAttributeWithContent(sentOrder));

        // then
        assertThat(same).isTrue();
    }

    @Test
    void reportsSameValue_whenCallbackMappingsAndTheirTargetsComeInAnotherOrder() {
        // given
        var storedOrder = createAttributeWithCallback(
                createMapping("algorithm", AttributeValueTarget.PATH_VARIABLE, AttributeValueTarget.REQUEST_PARAMETER),
                createMapping("curve", AttributeValueTarget.BODY));
        var sentOrder = createAttributeWithCallback(createMapping("curve", AttributeValueTarget.BODY),
                createMapping("algorithm", AttributeValueTarget.REQUEST_PARAMETER, AttributeValueTarget.PATH_VARIABLE));

        // when
        boolean same = AttributeDefinitionValues.sameValue(storedOrder, sentOrder);

        // then
        assertThat(same).isTrue();
    }

    @Test
    void reportsDifferentValue_whenACallbackMappingDiffers() {
        // given
        var stored = createAttributeWithCallback(createMapping("algorithm", AttributeValueTarget.PATH_VARIABLE));
        var changedTarget = createAttributeWithCallback(
                createMapping("algorithm", AttributeValueTarget.REQUEST_PARAMETER));

        // when
        boolean same = AttributeDefinitionValues.sameValue(stored, changedTarget);

        // then
        assertThat(same).isFalse();
    }

    @Test
    void reportsDifferentValue_whenADescriptionDiffers() {
        // given
        var stored = createAttribute();
        var changed = createAttribute();
        changed.setDescription("changed");

        // when
        boolean same = AttributeDefinitionValues.sameValue(stored, changed);

        // then
        assertThat(same).isFalse();
    }

    @Test
    void reportsDifferentValue_whenContentIsMissingOnOneSideAndEmptyOnTheOther() {
        // given
        var withoutContent = createAttribute();
        var withEmptyContent = createAttribute();
        withEmptyContent.setContent(List.of());

        // when
        boolean same = AttributeDefinitionValues.sameValue(withoutContent, withEmptyContent);

        // then
        assertThat(same).isFalse();
    }

    @Test
    void reportsSameValue_whenADateIsTypedOnOneSideAndTextOnTheOther() {
        // given
        var decryptedDate = LocalDate.of(2026, 11, 26);
        var sentDate = "2026-11-26";

        // when
        boolean same = AttributeDefinitionValues
                .sameValue(createAttributeWithContent(decryptedDate), createAttributeWithContent(sentDate));

        // then
        assertThat(same).isTrue();
    }

    @Test
    void reportsSameValue_whenANumberIsAFloatOnOneSideAndADoubleOnTheOther() {
        // given
        var decryptedFloat = 1.5f;
        var sentDouble = 1.5d;

        // when
        boolean same = AttributeDefinitionValues
                .sameValue(createAttributeWithContent(decryptedFloat), createAttributeWithContent(sentDouble));

        // then
        assertThat(same).isTrue();
    }

    @Test
    void reportsSameValue_whenTheSentDoubleRoundsToTheStoredFloat() {
        // given
        var decryptedFloat = Float.valueOf("3.14159265");
        var sentDouble = 3.14159265d;

        // when
        boolean same = AttributeDefinitionValues
                .sameValue(createAttributeWithContent(decryptedFloat), createAttributeWithContent(sentDouble));

        // then
        assertThat(same).isTrue();
    }

    @Test
    void reportsSameValue_whenTheSentIntegerEqualsTheStoredFloat() {
        // given
        var decryptedFloat = Float.valueOf("2");
        var sentInteger = 2;

        // when
        boolean same = AttributeDefinitionValues
                .sameValue(createAttributeWithContent(decryptedFloat), createAttributeWithContent(sentInteger));

        // then
        assertThat(same).isTrue();
    }

    @Test
    void reportsDifferentValue_whenANumberDiffers() {
        // given
        var storedFloat = 1.5f;
        var changedDouble = 2.5d;

        // when
        boolean same = AttributeDefinitionValues
                .sameValue(createAttributeWithContent(storedFloat), createAttributeWithContent(changedDouble));

        // then
        assertThat(same).isFalse();
    }

    // ── Helpers ───────────────────────────────────────────────────────────────

    private static DataAttributeV2 createAttribute() {
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

    private static DataAttributeV2 createAttributeWithContent(Serializable data) {
        DataAttributeV2 attribute = createAttribute();
        BaseAttributeContentV2<Serializable> content = new BaseAttributeContentV2<>();
        content.setReference("subjectAltName");
        content.setData(data);
        attribute.setContent(List.of(content));
        return attribute;
    }

    /** Builds the callback's sets in the given order, as a deserialized copy may iterate them. */
    private static DataAttributeV2 createAttributeWithCallback(AttributeCallbackMapping... mappings) {
        DataAttributeV2 attribute = createAttribute();
        AttributeCallback callback = new AttributeCallback();
        callback.setCallbackContext("/v1/keyspec/{algorithm}");
        callback.setCallbackMethod("GET");
        callback.setMappings(new LinkedHashSet<>(List.of(mappings)));
        attribute.setAttributeCallback(callback);
        return attribute;
    }

    private static AttributeCallbackMapping createMapping(String to, AttributeValueTarget... targets) {
        return new AttributeCallbackMapping("data_" + to, to, new LinkedHashSet<>(List.of(targets)));
    }
}
