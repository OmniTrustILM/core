package com.otilm.core.attribute;

import com.otilm.api.exception.ValidationException;
import com.otilm.api.model.client.attribute.RequestAttribute;
import com.otilm.api.model.client.attribute.RequestAttributeV2;
import com.otilm.api.model.client.attribute.RequestAttributeV3;
import com.otilm.api.model.common.attribute.common.AttributeContent;
import com.otilm.api.model.common.attribute.common.content.AttributeContentType;
import com.otilm.api.model.common.attribute.v2.content.StringAttributeContentV2;
import com.otilm.api.model.common.attribute.v3.content.BooleanAttributeContentV3;
import com.otilm.api.model.common.attribute.v3.content.StringAttributeContentV3;
import com.otilm.api.model.common.enums.cryptography.DigestAlgorithm;
import com.otilm.api.model.common.enums.cryptography.EncryptionAlgorithm;
import com.otilm.api.model.common.enums.cryptography.RsaEncryptionScheme;
import com.otilm.api.model.connector.cryptography.v2.operations.EncryptionAlgorithmAttribute;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Locale;
import java.util.UUID;
import java.util.stream.Stream;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.function.Executable;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.EnumSource;
import org.junit.jupiter.params.provider.MethodSource;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertNotSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Named.named;
import static org.junit.jupiter.params.provider.Arguments.arguments;

class EncryptionAlgorithmMappingTest {

    @ParameterizedTest
    @MethodSource("profiles")
    void toAttributes_returnsExactV3Fields(EncryptionAlgorithm algorithm, DigestAlgorithm hash) {
        // given
        List<RequestAttribute> expectedAttributes = splitAttributes(hash);

        // when
        List<RequestAttribute> attributes = EncryptionAlgorithmMapping.toAttributes(algorithm);

        // then
        assertEquals(describe(expectedAttributes), describe(attributes));
        attributes.forEach(attribute -> assertInstanceOf(RequestAttributeV3.class, attribute));
        if (hash != null) {
            RequestAttributeV3 mgf = (RequestAttributeV3) attributes.getLast();
            assertInstanceOf(BooleanAttributeContentV3.class, mgf.getContent().getFirst());
        }
        assertEquals(algorithm, EncryptionAlgorithmMapping.toAlgorithm(attributes));
    }

    @ParameterizedTest
    @MethodSource("profiles")
    void toAlgorithm_readsV2Fields_inReverseOrder(EncryptionAlgorithm expectedAlgorithm, DigestAlgorithm hash) {
        // given
        List<RequestAttribute> attributes = splitAttributes(hash).reversed();

        // when
        EncryptionAlgorithm algorithm = EncryptionAlgorithmMapping.toAlgorithm(attributes);

        // then
        assertEquals(expectedAlgorithm, algorithm);
    }

    @ParameterizedTest
    @EnumSource(EncryptionAlgorithm.class)
    void toAlgorithm_readsOriginalV3Selector(EncryptionAlgorithm expectedAlgorithm) {
        // given
        List<RequestAttribute> attributes = List.of(EncryptionAlgorithmAttribute.request(expectedAlgorithm));

        // when
        EncryptionAlgorithm algorithm = EncryptionAlgorithmMapping.toAlgorithm(attributes);

        // then
        assertEquals(expectedAlgorithm, algorithm);
    }

    @ParameterizedTest
    @EnumSource(EncryptionAlgorithm.class)
    void toAlgorithm_readsOriginalV2Selector_caseInsensitive(EncryptionAlgorithm expectedAlgorithm) {
        // given
        String code = expectedAlgorithm.getCode().toLowerCase(Locale.ROOT);
        List<RequestAttribute> attributes = List.of(originalV2(code));

        // when
        EncryptionAlgorithm algorithm = EncryptionAlgorithmMapping.toAlgorithm(attributes);

        // then
        assertEquals(expectedAlgorithm, algorithm);
    }

    @Test
    void toAlgorithm_readsMixedVersions_withoutDependingOnLabels() {
        // given
        EncryptionAlgorithm expectedAlgorithm = EncryptionAlgorithm.RSA_OAEP_SHA256;
        List<RequestAttribute> attributes = new ArrayList<>(splitAttributes(DigestAlgorithm.SHA_256));
        RequestAttributeV3 mgf = new RequestAttributeV3(
                UUID.fromString(RsaEncryptionAttributes.ATTRIBUTE_DATA_RSA_OAEP_USE_MGF_UUID),
                RsaEncryptionAttributes.ATTRIBUTE_DATA_RSA_OAEP_USE_MGF_NAME, AttributeContentType.BOOLEAN,
                List.of(new BooleanAttributeContentV3("Different label", true)));
        attributes.set(2, mgf);

        // when
        EncryptionAlgorithm algorithm = EncryptionAlgorithmMapping.toAlgorithm(attributes.reversed());

        // then
        assertEquals(expectedAlgorithm, algorithm);
    }

    @ParameterizedTest(name = "{0}")
    @MethodSource("invalidSelections")
    void toAlgorithm_refusesInvalidSelections(List<RequestAttribute> attributes, String expectedReason) {
        // given
        String expectedPrefix = "Encryption";

        // when
        Executable convert = () -> EncryptionAlgorithmMapping.toAlgorithm(attributes);

        // then
        ValidationException failure = assertThrows(ValidationException.class, convert);
        assertTrue(failure.getMessage().contains(expectedReason), failure.getMessage());
        assertTrue(failure.getMessage().contains(expectedPrefix)
                || failure.getMessage().contains(EncryptionAlgorithmAttribute.NAME));
    }

    @Test
    void toAttributes_returnsIndependentObjects() {
        // given
        EncryptionAlgorithm algorithm = EncryptionAlgorithm.RSA_OAEP_SHA256;
        List<RequestAttribute> previousAttributes = EncryptionAlgorithmMapping.toAttributes(algorithm);
        RequestAttributeV3 previousMgf = (RequestAttributeV3) previousAttributes.getLast();
        ((BooleanAttributeContentV3) previousMgf.getContent().getFirst()).setData(false);
        ((RequestAttributeV3) previousAttributes.getFirst()).setName("changed-scheme");
        List<RequestAttribute> expectedAttributes = splitAttributes(DigestAlgorithm.SHA_256);

        // when
        List<RequestAttribute> attributes = EncryptionAlgorithmMapping.toAttributes(algorithm);

        // then
        assertEquals(describe(expectedAttributes), describe(attributes));
        assertNotSame(previousMgf, attributes.getLast());
    }

    @Test
    void toAttributes_refusesNullAlgorithm() {
        // given
        EncryptionAlgorithm algorithm = null;

        // when
        Executable convert = () -> EncryptionAlgorithmMapping.toAttributes(algorithm);

        // then
        assertThrows(NullPointerException.class, convert);
    }

    @Test
    void toAlgorithm_refusesNullAttributes() {
        // given
        List<RequestAttribute> attributes = null;

        // when
        Executable convert = () -> EncryptionAlgorithmMapping.toAlgorithm(attributes);

        // then
        assertThrows(NullPointerException.class, convert);
    }

    private static Stream<Arguments> profiles() {
        return Stream
                .of(arguments(EncryptionAlgorithm.RSA_PKCS1_V1_5, null),
                        arguments(EncryptionAlgorithm.RSA_OAEP_SHA1, DigestAlgorithm.SHA_1),
                        arguments(EncryptionAlgorithm.RSA_OAEP_SHA256, DigestAlgorithm.SHA_256),
                        arguments(EncryptionAlgorithm.RSA_OAEP_SHA384, DigestAlgorithm.SHA_384),
                        arguments(EncryptionAlgorithm.RSA_OAEP_SHA512, DigestAlgorithm.SHA_512));
    }

    private static Stream<Arguments> invalidSelections() {
        RequestAttribute scheme = RsaEncryptionAttributes.buildRequestEncryptionScheme(RsaEncryptionScheme.OAEP);
        RequestAttribute hash = RsaEncryptionAttributes.buildRequestOaepHash(DigestAlgorithm.SHA_256);
        RequestAttributeV2 mgf = RsaEncryptionAttributes.buildRequestOaepMgf(true);
        RequestAttribute original = EncryptionAlgorithmAttribute.request(EncryptionAlgorithm.RSA_OAEP_SHA256);
        RequestAttributeV2 wrongUuid = RsaEncryptionAttributes.buildRequestOaepMgf(true);
        wrongUuid.setUuid(UUID.randomUUID());
        RequestAttributeV2 wrongName = RsaEncryptionAttributes.buildRequestOaepMgf(true);
        wrongName.setName("wrong-name");
        RequestAttributeV2 wrongType = RsaEncryptionAttributes.buildRequestOaepMgf(true);
        wrongType.setContentType(AttributeContentType.STRING);
        RequestAttributeV2 stringMgf = RsaEncryptionAttributes.buildRequestOaepMgf(true);
        stringMgf.setContent(List.of(new StringAttributeContentV2("true")));
        RequestAttributeV2 noContent = RsaEncryptionAttributes.buildRequestOaepMgf(true);
        noContent.setContent(null);
        RequestAttributeV2 noUuid = RsaEncryptionAttributes.buildRequestOaepMgf(true);
        noUuid.setUuid(null);
        RequestAttributeV2 noValue = RsaEncryptionAttributes.buildRequestOaepMgf(true);
        noValue.getContent().getFirst().setData(null);
        RequestAttributeV2 nullItem = RsaEncryptionAttributes.buildRequestOaepMgf(true);
        nullItem.setContent(Collections.singletonList(null));
        RequestAttributeV2 emptyContent = RsaEncryptionAttributes.buildRequestOaepMgf(true);
        emptyContent.setContent(List.of());
        RequestAttributeV2 multipleValues = RsaEncryptionAttributes.buildRequestOaepMgf(true);
        multipleValues.setContent(List.of(mgf.getContent().getFirst(), mgf.getContent().getFirst()));
        RequestAttributeV2 unsupportedType = RsaEncryptionAttributes.buildRequestOaepMgf(true);
        unsupportedType.setContentType(AttributeContentType.INTEGER);
        RequestAttributeV3 wrongV3Content = new RequestAttributeV3(mgf.getUuid(), mgf.getName(),
                AttributeContentType.BOOLEAN, List.of(new StringAttributeContentV3("true")));
        RequestAttributeV3 booleanOriginal = new RequestAttributeV3(EncryptionAlgorithmAttribute.ATTRIBUTE_UUID,
                EncryptionAlgorithmAttribute.NAME, AttributeContentType.BOOLEAN,
                List.of(new BooleanAttributeContentV3(true)));
        String noMatch = "do not match a known RSA field combination";
        return Stream
                .of(arguments(named("no attributes", List.of()), "must contain"),
                        arguments(named("too many attributes", List.of(scheme, hash, mgf, original)), "must contain"),
                        arguments(named("duplicate field", List.of(scheme, mgf, mgf)), "repeats an attribute UUID"),
                        arguments(named("duplicate selector", List.of(original, original)),
                                "repeats an attribute UUID"),
                        arguments(named("selector with split field", List.of(original, scheme)),
                                "must be supplied alone"),
                        arguments(named("unknown selector", List.of(originalV2("UNKNOWN"))), "unknown algorithm code"),
                        arguments(named("boolean selector", List.of(booleanOriginal)), "string algorithm code"),
                        arguments(named("missing OAEP hash", List.of(scheme, mgf)), noMatch),
                        arguments(named("missing OAEP MGF", List.of(scheme, hash)), noMatch),
                        arguments(named("missing scheme", List.of(hash, mgf)), noMatch),
                        arguments(
                                named("MGF false",
                                        List.of(scheme, hash, RsaEncryptionAttributes.buildRequestOaepMgf(false))),
                                noMatch),
                        arguments(named("unsupported digest", splitAttributes(DigestAlgorithm.MD5)), noMatch),
                        arguments(named("PKCS1 with OAEP fields", List
                                .of(RsaEncryptionAttributes
                                        .buildRequestEncryptionScheme(RsaEncryptionScheme.PKCS1_v1_5), hash, mgf)),
                                noMatch),
                        arguments(named("wrong UUID", List.of(scheme, hash, wrongUuid)), noMatch),
                        arguments(named("wrong name", List.of(scheme, hash, wrongName)), noMatch),
                        arguments(named("boolean under string type", List.of(wrongType)), "non-null string value"),
                        arguments(named("string under boolean type", List.of(stringMgf)), "non-null boolean value"),
                        arguments(named("wrong V3 content type", List.of(wrongV3Content)), "BOOLEAN content"),
                        arguments(named("unsupported content type", List.of(unsupportedType)), "STRING or BOOLEAN"),
                        arguments(named("null content", List.of(noContent)), "list of values"),
                        arguments(named("null UUID", List.of(noUuid)), "must have a UUID"),
                        arguments(named("null value", List.of(noValue)), "non-null boolean value"),
                        arguments(named("null item", List.of(nullItem)), "non-null attribute content item"),
                        arguments(named("empty content", List.of(emptyContent)), "exactly one value"),
                        arguments(named("multiple values", List.of(multipleValues)), "exactly one value"),
                        arguments(named("null attribute", Collections.singletonList(null)), "must not be null"));
    }

    private static List<RequestAttribute> splitAttributes(DigestAlgorithm hash) {
        if (hash == null) {
            return List.of(RsaEncryptionAttributes.buildRequestEncryptionScheme(RsaEncryptionScheme.PKCS1_v1_5));
        }
        RequestAttribute scheme = RsaEncryptionAttributes.buildRequestEncryptionScheme(RsaEncryptionScheme.OAEP);
        RequestAttribute hashAttribute = RsaEncryptionAttributes.buildRequestOaepHash(hash);
        RequestAttribute mgf = RsaEncryptionAttributes.buildRequestOaepMgf(true);
        return List.of(scheme, hashAttribute, mgf);
    }

    private static RequestAttributeV2 originalV2(String code) {
        RequestAttributeV2 attribute = new RequestAttributeV2();
        attribute.setUuid(EncryptionAlgorithmAttribute.ATTRIBUTE_UUID);
        attribute.setName(EncryptionAlgorithmAttribute.NAME);
        attribute.setContentType(AttributeContentType.STRING);
        attribute.setContent(List.of(new StringAttributeContentV2(code)));
        return attribute;
    }

    private static List<String> describe(List<RequestAttribute> attributes) {
        return attributes.stream().map(attribute -> {
            List<? extends AttributeContent> content = attribute.getContent();
            Object value = content.getFirst().getData();
            return attribute.getUuid() + "|" + attribute.getName() + "|" + attribute.getContentType() + "|" + value;
        }).toList();
    }
}
