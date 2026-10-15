package com.otilm.core.attribute;

import com.otilm.api.exception.ConnectorException;
import com.otilm.api.model.common.attribute.common.AttributeContent;
import com.otilm.api.model.common.attribute.common.BaseAttribute;
import com.otilm.api.model.common.attribute.common.content.AttributeContentType;
import com.otilm.api.model.common.attribute.v2.DataAttributeV2;
import com.otilm.api.model.common.attribute.v3.DataAttributeV3;
import com.otilm.api.model.common.attribute.v3.content.StringAttributeContentV3;
import com.otilm.api.model.common.enums.cryptography.EncryptionAlgorithm;
import com.otilm.api.model.connector.cryptography.v2.operations.EncryptionAlgorithmAttribute;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.UUID;
import java.util.stream.Stream;
import org.junit.jupiter.api.Named;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.function.Executable;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Named.named;

/**
 * Verifies encryption offers retain their presentation contract and classify malformed schemas as connector faults.
 */
class EncryptionAlgorithmUtilsTest {

    @Test
    void expandEncryptionAlgorithmDefinition_mergesChoices_preservingOrderAndOriginalDefinitions()
            throws ConnectorException {
        // given
        DataAttributeV3 original = EncryptionAlgorithmAttribute
                .definition(List
                        .of(EncryptionAlgorithm.RSA_PKCS1_V1_5, EncryptionAlgorithm.RSA_OAEP_SHA256,
                                EncryptionAlgorithm.RSA_OAEP_SHA384, EncryptionAlgorithm.RSA_OAEP_SHA256));
        DataAttributeV3 unrelated = unrelatedDefinition();
        List<BaseAttribute> schema = List.of(unrelated, original);
        Object originalContent = original.getContent();

        // when
        List<BaseAttribute> presented = EncryptionAlgorithmUtils.expandEncryptionAlgorithmDefinition(schema);

        // then
        assertSame(unrelated, presented.getFirst());
        assertEquals(List.of("PKCS1-v1_5", "OAEP"), values(presented.get(1)));
        assertEquals(List.of("SHA-256", "SHA-384"), values(presented.get(2)));
        assertEquals(List.of(true), values(presented.get(3)));
        assertEquals(AttributeContentType.BOOLEAN, ((DataAttributeV3) presented.get(3)).getContentType());
        assertEquals(RsaEncryptionAttributes.ATTRIBUTE_DATA_RSA_OAEP_USE_MGF_NAME, presented.get(3).getName());
        assertTrue(((DataAttributeV3) presented.get(1)).getProperties().isRequired());
        assertFalse(((DataAttributeV3) presented.get(2)).getProperties().isRequired());
        assertFalse(((DataAttributeV3) presented.get(3)).getProperties().isRequired());
        assertTrue(((DataAttributeV3) presented.get(3)).getProperties().isReadOnly());
        assertSame(originalContent, original.getContent());
    }

    @Test
    void expandEncryptionAlgorithmDefinition_keepsOnlyScheme_forPkcs1() throws ConnectorException {
        // given
        List<BaseAttribute> schema = List
                .of(EncryptionAlgorithmAttribute.definition(List.of(EncryptionAlgorithm.RSA_PKCS1_V1_5)));

        // when
        List<BaseAttribute> presented = EncryptionAlgorithmUtils.expandEncryptionAlgorithmDefinition(schema);

        // then
        assertEquals(1, presented.size());
        assertEquals(RsaEncryptionAttributes.ATTRIBUTE_DATA_RSA_ENC_SCHEME_NAME, presented.getFirst().getName());
        assertEquals(List.of("PKCS1-v1_5"), values(presented.getFirst()));
        assertTrue(((DataAttributeV3) presented.getFirst()).getProperties().isRequired());
    }

    @Test
    void expandEncryptionAlgorithmDefinition_requiresAllFieldsAndFixesMgf_forOaepOnly() throws ConnectorException {
        // given
        List<BaseAttribute> schema = List
                .of(EncryptionAlgorithmAttribute.definition(List.of(EncryptionAlgorithm.RSA_OAEP_SHA256)));

        // when
        List<BaseAttribute> presented = EncryptionAlgorithmUtils.expandEncryptionAlgorithmDefinition(schema);

        // then
        assertEquals(3, presented.size());
        assertTrue(((DataAttributeV3) presented.get(0)).getProperties().isRequired());
        assertTrue(((DataAttributeV3) presented.get(1)).getProperties().isRequired());
        assertTrue(((DataAttributeV3) presented.get(2)).getProperties().isRequired());
        assertTrue(((DataAttributeV3) presented.get(2)).getProperties().isReadOnly());
        assertEquals(List.of(true), values(presented.getLast()));
    }

    @Test
    void expandEncryptionAlgorithmDefinition_preservesLegacyTemplateRequirements() throws ConnectorException {
        // given
        List<BaseAttribute> schema = List
                .of(EncryptionAlgorithmAttribute.definition(List.of(EncryptionAlgorithm.RSA_OAEP_SHA256)));

        // when
        EncryptionAlgorithmUtils.expandEncryptionAlgorithmDefinition(schema);

        // then
        DataAttributeV2 legacyScheme = (DataAttributeV2) RsaEncryptionAttributes.buildDataEncryptionScheme();
        DataAttributeV2 legacyHash = (DataAttributeV2) RsaEncryptionAttributes.buildDataOaepHash();
        DataAttributeV2 legacyMgf = (DataAttributeV2) RsaEncryptionAttributes.buildDataOaepMgf();
        assertFalse(legacyScheme.getProperties().isRequired());
        assertTrue(legacyHash.getProperties().isRequired());
        assertFalse(legacyMgf.getProperties().isRequired());
        assertFalse(legacyMgf.getProperties().isReadOnly());
    }

    @Test
    void expandEncryptionAlgorithmDefinition_keepsSchema_withoutAlgorithmDefinition() throws ConnectorException {
        // given
        List<BaseAttribute> schema = List.of(unrelatedDefinition());

        // when
        List<BaseAttribute> presented = EncryptionAlgorithmUtils.expandEncryptionAlgorithmDefinition(schema);

        // then
        assertSame(schema, presented);
    }

    @ParameterizedTest
    @MethodSource("invalidSchemas")
    void expandEncryptionAlgorithmDefinition_rejectsMalformedOrConflictingDefinitions(List<BaseAttribute> schema)
            throws ConnectorException {
        // given
        String expectedMessagePrefix = "Connector ";

        // when
        Executable expand = () -> EncryptionAlgorithmUtils.expandEncryptionAlgorithmDefinition(schema);

        // then
        ConnectorException failure = assertThrows(ConnectorException.class, expand);
        assertTrue(failure.getMessage().contains(expectedMessagePrefix));
    }

    @ParameterizedTest(name = "{0}")
    @MethodSource("mismatchedIdentitySchemas")
    void expandEncryptionAlgorithmDefinition_rejectsMismatchedReservedIdentity(List<BaseAttribute> schema) {
        // given
        String expectedMessage = "Connector publishes mismatched encryptionAlgorithm attribute UUID and name.";

        // when
        Executable expand = () -> EncryptionAlgorithmUtils.expandEncryptionAlgorithmDefinition(schema);

        // then
        ConnectorException failure = assertThrows(ConnectorException.class, expand);
        assertEquals(expectedMessage, failure.getMessage());
    }

    @ParameterizedTest(name = "{0}")
    @MethodSource("schemasWithNullDefinitions")
    void expandEncryptionAlgorithmDefinition_rejectsNullDefinitions(List<BaseAttribute> schema) {
        // given
        String expectedMessage = "Connector publishes a null attribute definition.";

        // when
        Executable expand = () -> EncryptionAlgorithmUtils.expandEncryptionAlgorithmDefinition(schema);

        // then
        ConnectorException failure = assertThrows(ConnectorException.class, expand);
        assertEquals(expectedMessage, failure.getMessage());
    }

    private static Stream<Named<List<BaseAttribute>>> schemasWithNullDefinitions() {
        DataAttributeV3 selector = EncryptionAlgorithmAttribute
                .definition(List.of(EncryptionAlgorithm.RSA_OAEP_SHA256));
        return Stream
                .of(named("null before selector", Arrays.asList(null, selector)),
                        named("null after selector", Arrays.asList(selector, null)),
                        named("null without selector", Collections.singletonList(null)));
    }

    private static Stream<Named<List<BaseAttribute>>> mismatchedIdentitySchemas() {
        DataAttributeV3 valid = EncryptionAlgorithmAttribute.definition(List.of(EncryptionAlgorithm.RSA_OAEP_SHA256));
        DataAttributeV3 wrongUuid = EncryptionAlgorithmAttribute
                .definition(List.of(EncryptionAlgorithm.RSA_OAEP_SHA256));
        wrongUuid.setUuid(UUID.randomUUID().toString());
        DataAttributeV3 wrongName = EncryptionAlgorithmAttribute
                .definition(List.of(EncryptionAlgorithm.RSA_OAEP_SHA256));
        wrongName.setName("connector-option");
        DataAttributeV3 missingUuid = EncryptionAlgorithmAttribute
                .definition(List.of(EncryptionAlgorithm.RSA_OAEP_SHA256));
        missingUuid.setUuid(null);
        DataAttributeV3 missingName = EncryptionAlgorithmAttribute
                .definition(List.of(EncryptionAlgorithm.RSA_OAEP_SHA256));
        missingName.setName(null);
        return Stream
                .of(named("wrong UUID", List.of(wrongUuid)), named("wrong name", List.of(wrongName)),
                        named("missing UUID", List.of(missingUuid)), named("missing name", List.of(missingName)),
                        named("wrong UUID after valid entry", List.of(valid, wrongUuid)),
                        named("wrong name before valid entry", List.of(wrongName, valid)));
    }

    private static Stream<List<BaseAttribute>> invalidSchemas() {
        DataAttributeV3 valid = EncryptionAlgorithmAttribute.definition(List.of(EncryptionAlgorithm.RSA_OAEP_SHA256));
        DataAttributeV3 empty = EncryptionAlgorithmAttribute.definition(List.of());
        DataAttributeV3 unknown = EncryptionAlgorithmAttribute.definition(List.of(EncryptionAlgorithm.RSA_OAEP_SHA256));
        unknown.setContent(List.of(new StringAttributeContentV3("unknown")));
        DataAttributeV3 missingContent = EncryptionAlgorithmAttribute
                .definition(List.of(EncryptionAlgorithm.RSA_OAEP_SHA256));
        missingContent.setContent(null);
        DataAttributeV3 conflictingName = unrelatedDefinition();
        conflictingName.setName(RsaEncryptionAttributes.ATTRIBUTE_DATA_RSA_OAEP_HASH_NAME);
        DataAttributeV3 conflictingUuid = unrelatedDefinition();
        conflictingUuid.setUuid(RsaEncryptionAttributes.ATTRIBUTE_DATA_RSA_ENC_SCHEME_UUID);
        return Stream
                .of(List.of(valid, valid), List.of(empty), List.of(unknown), List.of(missingContent),
                        List.of(valid, conflictingName), List.of(valid, conflictingUuid));
    }

    private static DataAttributeV3 unrelatedDefinition() {
        DataAttributeV3 definition = new DataAttributeV3();
        definition.setUuid(UUID.randomUUID().toString());
        definition.setName("connector-option");
        return definition;
    }

    private static List<Object> values(BaseAttribute definition) {
        return ((List<?>) definition.getContent()).stream().map(value -> ((AttributeContent) value).getData()).toList();
    }
}
