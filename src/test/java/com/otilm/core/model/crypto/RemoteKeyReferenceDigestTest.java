package com.otilm.core.model.crypto;

import com.otilm.api.model.common.attribute.common.AttributeContent;
import com.otilm.api.model.common.attribute.common.MetadataAttribute;
import com.otilm.api.model.common.attribute.common.content.AttributeContentType;
import com.otilm.api.model.common.attribute.common.properties.MetadataAttributeProperties;
import com.otilm.api.model.common.attribute.v2.MetadataAttributeV2;
import com.otilm.api.model.common.attribute.v2.content.StringAttributeContentV2;
import com.otilm.api.model.common.attribute.v3.MetadataAttributeV3;
import com.otilm.api.model.common.attribute.v3.content.IntegerAttributeContentV3;
import com.otilm.api.model.common.attribute.v3.content.ObjectAttributeContentV3;
import com.otilm.api.model.common.attribute.v3.content.StringAttributeContentV3;
import com.otilm.core.model.crypto.RemoteKeyReference.MetadataReference;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.UUID;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

class RemoteKeyReferenceDigestTest {

    @Test
    void returnsALowercaseSha256Hex() {
        // given
        var handle = new MetadataReference(List.of(buildKeyId("a1b2")));

        // when
        String digest = handle.digest();

        // then
        assertThat(digest).matches("[0-9a-f]{64}");
    }

    @Test
    void returnsTheSameDigest_whenTheAttributesComeInAnotherOrder() {
        // given
        var keyId = buildKeyId("a1b2");
        var objectClass = buildObjectClass("CKO_PRIVATE_KEY");
        var handle = new MetadataReference(List.of(keyId, objectClass));
        var reordered = new MetadataReference(List.of(objectClass, keyId));

        // when
        String digest = reordered.digest();

        // then
        assertThat(digest).isEqualTo(handle.digest());
    }

    @Test
    void returnsTheSameDigest_whenOnlyTheDecorationOfAnAttributeDiffers() {
        // given
        var handle = new MetadataReference(List.of(buildKeyId("a1b2")));
        var decorated = new MetadataReference(List.of(buildDecoratedKeyId("a1b2")));

        // when
        String digest = decorated.digest();

        // then
        assertThat(digest).isEqualTo(handle.digest());
    }

    @Test
    void returnsTheSameDigest_whenTheMembersOfAnObjectValueComeInAnotherOrder() {
        // given
        var slotFirst = new LinkedHashMap<String, String>();
        slotFirst.put("slot", "1");
        slotFirst.put("keyId", "a1b2");
        var keyIdFirst = new LinkedHashMap<String, String>();
        keyIdFirst.put("keyId", "a1b2");
        keyIdFirst.put("slot", "1");
        var handle = new MetadataReference(
                List.of(buildAttribute("location", new ObjectAttributeContentV3(slotFirst))));
        var reordered = new MetadataReference(
                List.of(buildAttribute("location", new ObjectAttributeContentV3(keyIdFirst))));

        // when
        String digest = reordered.digest();

        // then
        assertThat(digest).isEqualTo(handle.digest());
    }

    @Test
    void returnsAnotherDigest_whenAValueDiffers() {
        // given
        var handle = new MetadataReference(List.of(buildKeyId("a1b2"), buildObjectClass("CKO_PRIVATE_KEY")));
        var otherKeyId = new MetadataReference(List.of(buildKeyId("a1b3"), buildObjectClass("CKO_PRIVATE_KEY")));

        // when
        String digest = otherKeyId.digest();

        // then
        assertThat(digest).isNotEqualTo(handle.digest());
    }

    @Test
    void returnsAnotherDigest_whenANameDiffers() {
        // given
        var handle = new MetadataReference(List.of(buildAttribute("keyId", new StringAttributeContentV3("a1b2"))));
        var otherName = new MetadataReference(List.of(buildAttribute("alias", new StringAttributeContentV3("a1b2"))));

        // when
        String digest = otherName.digest();

        // then
        assertThat(digest).isNotEqualTo(handle.digest());
    }

    @Test
    void returnsAnotherDigest_whenAValueHasAnotherType() {
        // given
        var handle = new MetadataReference(List.of(buildAttribute("slot", new StringAttributeContentV3("1"))));
        var numericSlot = new MetadataReference(List.of(buildAttribute("slot", new IntegerAttributeContentV3(1))));

        // when
        String digest = numericSlot.digest();

        // then
        assertThat(digest).isNotEqualTo(handle.digest());
    }

    @Test
    void returnsAnotherDigest_whenValuesMoveBetweenAttributes() {
        // given
        var handle = new MetadataReference(List
                .of(buildAttribute("first", new StringAttributeContentV3("a"), new StringAttributeContentV3("b")),
                        buildAttribute("second", new StringAttributeContentV3("c"))));
        var shifted = new MetadataReference(List
                .of(buildAttribute("first", new StringAttributeContentV3("a")), buildAttribute("second",
                        new StringAttributeContentV3("b"), new StringAttributeContentV3("c"))));

        // when
        String digest = shifted.digest();

        // then
        assertThat(digest).isNotEqualTo(handle.digest());
    }

    @Test
    void returnsAnotherDigest_whenTheValuesOfAnAttributeComeInAnotherOrder() {
        // given
        var handle = new MetadataReference(
                List.of(buildAttribute("path", new StringAttributeContentV3("a"), new StringAttributeContentV3("b"))));
        var reordered = new MetadataReference(
                List.of(buildAttribute("path", new StringAttributeContentV3("b"), new StringAttributeContentV3("a"))));

        // when
        String digest = reordered.digest();

        // then
        assertThat(digest).isNotEqualTo(handle.digest());
    }

    @Test
    void returnsNoDigest_whenTheHandleIsEmpty() {
        // given
        var emptyHandle = new MetadataReference(List.of());

        // when
        String digest = emptyHandle.digest();

        // then
        assertThat(digest).isNull();
    }

    // ── Helpers ───────────────────────────────────────────────────────────────

    private static MetadataAttribute buildKeyId(String value) {
        return buildAttribute("keyId", new StringAttributeContentV3(value));
    }

    private static MetadataAttribute buildObjectClass(String value) {
        return buildAttribute("pkcs11ObjectClass", new StringAttributeContentV3(value));
    }

    /**
     * The key ID as an older connector sends it: another attribute version, a UUID, a label and a content reference.
     */
    private static MetadataAttribute buildDecoratedKeyId(String value) {
        var properties = new MetadataAttributeProperties();
        properties.setLabel("Key ID");
        properties.setVisible(false);
        var attribute = new MetadataAttributeV2();
        attribute.setUuid(UUID.randomUUID().toString());
        attribute.setName("keyId");
        attribute.setContentType(AttributeContentType.STRING);
        attribute.setProperties(properties);
        attribute.setContent(List.of(new StringAttributeContentV2("CKA_ID", value)));
        return attribute;
    }

    private static MetadataAttribute buildAttribute(String name, AttributeContent... content) {
        var attribute = new MetadataAttributeV3();
        attribute.setUuid(UUID.randomUUID().toString());
        attribute.setName(name);
        attribute.setContentType(content[0].getContentType());
        attribute.setProperties(new MetadataAttributeProperties());
        attribute.setContent(List.of(content));
        return attribute;
    }
}
