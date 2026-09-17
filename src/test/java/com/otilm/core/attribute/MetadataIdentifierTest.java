package com.otilm.core.attribute;

import com.otilm.api.model.common.attribute.common.MetadataAttribute;
import com.otilm.api.model.common.attribute.common.content.AttributeContentType;
import com.otilm.api.model.common.attribute.common.content.data.ProtectionLevel;
import com.otilm.api.model.common.attribute.common.properties.MetadataAttributeProperties;
import com.otilm.api.model.common.attribute.v2.MetadataAttributeV2;
import com.otilm.api.model.common.attribute.v2.content.IntegerAttributeContentV2;
import com.otilm.api.model.common.attribute.v2.content.StringAttributeContentV2;
import com.otilm.api.model.common.attribute.v3.MetadataAttributeV3;
import com.otilm.api.model.common.attribute.v3.content.StringAttributeContentV3;
import java.util.Arrays;
import java.util.List;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;
import org.junit.jupiter.params.provider.NullAndEmptySource;
import org.junit.jupiter.params.provider.ValueSource;

import static org.junit.jupiter.api.Assertions.assertEquals;

class MetadataIdentifierTest {

    @Test
    void format_includesMultipleAttributesAndNumericValues() {
        // given
        int slotNumber = 3;
        MetadataAttributeV2 alias = stringAttribute("alias", "signing-key");
        MetadataAttributeV2 slot = new MetadataAttributeV2();
        slot.setName("slot");
        slot.setContentType(AttributeContentType.INTEGER);
        slot.setContent(List.of(new IntegerAttributeContentV2(slotNumber)));
        List<? extends MetadataAttribute> metadata = List.of(alias, slot);

        // when
        String identifier = MetadataIdentifier.format(metadata);

        // then
        assertEquals("{alias=[signing-key], slot=[3]}", identifier);
    }

    @ParameterizedTest
    @NullAndEmptySource
    void format_handlesMissingMetadata(List<MetadataAttribute> attributes) {
        // given
        List<? extends MetadataAttribute> metadata = attributes;

        // when
        String identifier = MetadataIdentifier.format(metadata);

        // then
        assertEquals("{}", identifier);
    }

    @Test
    void format_handlesNullEntriesAndValues() {
        // given
        MetadataAttributeV2 attribute = stringAttribute("handle", "unused");
        attribute.setContent(Arrays.asList(null, new StringAttributeContentV2()));
        List<? extends MetadataAttribute> metadata = Arrays.asList(null, attribute);

        // when
        String identifier = MetadataIdentifier.format(metadata);

        // then
        assertEquals("{null, handle=[null, null]}", identifier);
    }

    @Test
    void format_redactsUnknownContentType() {
        // given
        MetadataAttributeV2 attribute = stringAttribute("handle", "sensitive-provider-value");
        attribute.setContentType(null);
        List<? extends MetadataAttribute> metadata = List.of(attribute);

        // when
        String identifier = MetadataIdentifier.format(metadata);

        // then
        assertEquals("{handle=[redacted]}", identifier);
    }

    @ParameterizedTest
    @ValueSource(ints = {2, 3})
    void format_includesEveryValueAndEscapesLineBreaks(int version) {
        // given
        String attributeName = "key\nlabel";
        List<String> values = List.of("signing\r\nkey", "secondary-key");
        MetadataAttribute attribute = stringAttribute(version, attributeName, values);
        List<? extends MetadataAttribute> metadata = List.of(attribute);

        // when
        String identifier = MetadataIdentifier.format(metadata);

        // then
        assertEquals("{key\\nlabel=[signing\\r\\nkey, secondary-key]}", identifier);
    }

    @Test
    void format_redactsProtectedAndHiddenValues() {
        // given
        MetadataAttribute encrypted = stringAttribute("protected-key", "encrypted-key-handle");
        MetadataAttribute hidden = stringAttribute("hidden-key", "hidden-key-handle");
        MetadataAttributeProperties encryptedProperties = new MetadataAttributeProperties();
        encryptedProperties.setProtectionLevel(ProtectionLevel.ENCRYPTED);
        ((MetadataAttributeV2) encrypted).setProperties(encryptedProperties);
        MetadataAttributeProperties hiddenProperties = new MetadataAttributeProperties();
        hiddenProperties.setVisible(false);
        ((MetadataAttributeV2) hidden).setProperties(hiddenProperties);
        List<? extends MetadataAttribute> metadata = List.of(encrypted, hidden);

        // when
        String identifier = MetadataIdentifier.format(metadata);

        // then
        assertEquals("{protected-key=[redacted], hidden-key=[redacted]}", identifier);
    }

    @ParameterizedTest
    @EnumSource(value = AttributeContentType.class,
            names = {"SECRET", "CREDENTIAL", "FILE", "OBJECT", "RESOURCE", "CODEBLOCK"})
    void format_redactsNonScalarTypes_evenWhenDataIsString(AttributeContentType type) {
        // given
        MetadataAttributeV2 attribute = stringAttribute("handle", "sensitive-provider-value");
        attribute.setContentType(type);
        List<? extends MetadataAttribute> metadata = List.of(attribute);

        // when
        String identifier = MetadataIdentifier.format(metadata);

        // then
        assertEquals("{handle=[redacted]}", identifier);
    }

    @Test
    void format_redactsMismatchedValueType() {
        // given
        MetadataAttributeV2 attribute = stringAttribute("slot", "sensitive-provider-value");
        attribute.setContentType(AttributeContentType.INTEGER);
        List<? extends MetadataAttribute> metadata = List.of(attribute);

        // when
        String identifier = MetadataIdentifier.format(metadata);

        // then
        assertEquals("{slot=[[redacted]]}", identifier);
    }

    @Test
    void format_redactsConflictingContentType() {
        // given
        MetadataAttributeV3 attribute = (MetadataAttributeV3) stringAttribute(3, "handle", List.of("provider-value"));
        attribute.getContent().getFirst().setContentType(AttributeContentType.RESOURCE);
        List<? extends MetadataAttribute> metadata = List.of(attribute);

        // when
        String identifier = MetadataIdentifier.format(metadata);

        // then
        assertEquals("{handle=[[redacted]]}", identifier);
    }

    @Test
    void format_handlesMissingContent() {
        // given
        MetadataAttributeV2 attribute = stringAttribute("handle", "unused");
        attribute.setContent(null);
        List<? extends MetadataAttribute> metadata = List.of(attribute);

        // when
        String identifier = MetadataIdentifier.format(metadata);

        // then
        assertEquals("{handle=[]}", identifier);
    }

    private static MetadataAttributeV2 stringAttribute(String name, String value) {
        return (MetadataAttributeV2) stringAttribute(2, name, List.of(value));
    }

    private static MetadataAttribute stringAttribute(int version, String name, List<String> values) {
        if (version == 3) {
            MetadataAttributeV3 attribute = new MetadataAttributeV3();
            attribute.setName(name);
            attribute.setContentType(AttributeContentType.STRING);
            attribute.setContent(values.stream().map(StringAttributeContentV3::new).toList());
            return attribute;
        }
        MetadataAttributeV2 attribute = new MetadataAttributeV2();
        attribute.setName(name);
        attribute.setContentType(AttributeContentType.STRING);
        attribute.setContent(values.stream().map(StringAttributeContentV2::new).toList());
        return attribute;
    }
}
