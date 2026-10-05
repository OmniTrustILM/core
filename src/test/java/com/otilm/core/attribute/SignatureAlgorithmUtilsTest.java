package com.otilm.core.attribute;

import com.otilm.api.exception.ConnectorException;
import com.otilm.api.model.common.attribute.common.AttributeContent;
import com.otilm.api.model.common.attribute.common.BaseAttribute;
import com.otilm.api.model.common.attribute.common.content.AttributeContentType;
import com.otilm.api.model.common.attribute.v3.DataAttributeV3;
import com.otilm.api.model.common.attribute.v3.content.IntegerAttributeContentV3;
import com.otilm.api.model.common.attribute.v3.content.StringAttributeContentV3;
import com.otilm.api.model.common.enums.cryptography.SignatureAlgorithm;
import com.otilm.api.model.connector.cryptography.v2.operations.SignatureAlgorithmAttribute;
import java.util.List;
import java.util.UUID;
import java.util.stream.Stream;
import org.junit.jupiter.api.Named;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.function.Executable;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.EnumSource;
import org.junit.jupiter.params.provider.MethodSource;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Named.named;
import static org.junit.jupiter.params.provider.Arguments.arguments;

/**
 * Verifies connector signature schemas are expanded without misclassifying schema faults as caller errors.
 */
class SignatureAlgorithmUtilsTest {

    @Test
    void expandSignatureAlgorithmDefinition_mergesRsaChoices_inTheOriginalPosition_withoutMutatingConnectorDefinitions()
            throws ConnectorException {
        // given
        BaseAttribute before = unrelatedDefinition("before");
        BaseAttribute after = unrelatedDefinition("after");
        DataAttributeV3 original = SignatureAlgorithmAttribute
                .definition(List
                        .of(SignatureAlgorithm.SHA256_WITH_RSA, SignatureAlgorithm.SHA384_WITH_RSA_PSS,
                                SignatureAlgorithm.SHA384_WITH_RSA, SignatureAlgorithm.SHA256_WITH_RSA_PSS));
        List<String> originalCodes = values(original);
        List<BaseAttribute> schema = List.of(before, original, after);

        // when
        List<BaseAttribute> presented = SignatureAlgorithmUtils.expandSignatureAlgorithmDefinition(schema);

        // then
        assertEquals(List
                .of("before", RsaSignatureAttributes.ATTRIBUTE_DATA_RSA_SIG_SCHEME,
                        RsaSignatureAttributes.ATTRIBUTE_DATA_SIG_DIGEST, "after"),
                names(presented));
        assertSame(before, presented.getFirst());
        assertSame(after, presented.getLast());
        assertEquals(List.of("PKCS1-v1_5", "PSS"), values(presented.get(1)));
        assertEquals(List.of("SHA-256", "SHA-384"), values(presented.get(2)));
        assertEquals(originalCodes, values(original));
        assertSame(original, schema.get(1));
        assertSplitDefinition(presented.get(1), RsaSignatureAttributes.ATTRIBUTE_DATA_RSA_SIG_SCHEME_UUID);
        assertSplitDefinition(presented.get(2), RsaSignatureAttributes.ATTRIBUTE_DATA_SIG_DIGEST_UUID);
    }

    @Test
    void expandSignatureAlgorithmDefinition_presentsOnlyDigestChoices_forEcdsa() throws ConnectorException {
        // given
        List<BaseAttribute> schema = List
                .of(SignatureAlgorithmAttribute
                        .definition(
                                List.of(SignatureAlgorithm.SHA384_WITH_ECDSA, SignatureAlgorithm.SHA256_WITH_ECDSA)));

        // when
        List<BaseAttribute> presented = SignatureAlgorithmUtils.expandSignatureAlgorithmDefinition(schema);

        // then
        assertEquals(List.of(RsaSignatureAttributes.ATTRIBUTE_DATA_SIG_DIGEST), names(presented));
        assertEquals(List.of("SHA-384", "SHA-256"), values(presented.getFirst()));
        assertSplitDefinition(presented.getFirst(), RsaSignatureAttributes.ATTRIBUTE_DATA_SIG_DIGEST_UUID);
    }

    @Test
    void expandSignatureAlgorithmDefinition_deduplicatesRepeatedAlgorithmsAndFieldValues() throws ConnectorException {
        // given
        List<BaseAttribute> schema = List
                .of(SignatureAlgorithmAttribute
                        .definition(List
                                .of(SignatureAlgorithm.SHA256_WITH_RSA, SignatureAlgorithm.SHA256_WITH_RSA,
                                        SignatureAlgorithm.SHA256_WITH_RSA_PSS)));

        // when
        List<BaseAttribute> presented = SignatureAlgorithmUtils.expandSignatureAlgorithmDefinition(schema);

        // then
        assertEquals(List.of("PKCS1-v1_5", "PSS"), values(presented.getFirst()));
        assertEquals(List.of("SHA-256"), values(presented.get(1)));
    }

    @ParameterizedTest
    @EnumSource(value = SignatureAlgorithm.class, names = {"ML_DSA_65", "FALCON_1024", "ED25519"})
    void expandSignatureAlgorithmDefinition_keepsOriginalDefinition_forAlgorithmsWithoutSplitFields(
            SignatureAlgorithm algorithm) throws ConnectorException {
        // given
        DataAttributeV3 original = SignatureAlgorithmAttribute.definition(List.of(algorithm));
        List<BaseAttribute> schema = List.of(original);

        // when
        List<BaseAttribute> presented = SignatureAlgorithmUtils.expandSignatureAlgorithmDefinition(schema);

        // then
        assertSame(schema, presented);
        assertSame(original, presented.getFirst());
        assertEquals(List.of(algorithm.getCode()), values(presented.getFirst()));
    }

    @ParameterizedTest(name = "{0}")
    @MethodSource("schemasWithNoSplitConversion")
    void expandSignatureAlgorithmDefinition_keepsOriginalSchema_whenNoSplitConversionIsNeeded(
            List<BaseAttribute> schema) throws ConnectorException {
        // given
        List<BaseAttribute> originalSchema = schema;

        // when
        List<BaseAttribute> presented = SignatureAlgorithmUtils.expandSignatureAlgorithmDefinition(schema);

        // then
        assertSame(originalSchema, presented);
    }

    private static Stream<Named<List<BaseAttribute>>> schemasWithNoSplitConversion() {
        DataAttributeV3 wrongUuid = SignatureAlgorithmAttribute.definition(List.of(SignatureAlgorithm.SHA256_WITH_RSA));
        wrongUuid.setUuid("ae2b12c7-8718-4cb4-a8ad-a34dbd48cfa2");
        return Stream
                .of(named("two ML-DSA choices", List
                        .of(SignatureAlgorithmAttribute
                                .definition(List.of(SignatureAlgorithm.ML_DSA_44, SignatureAlgorithm.ML_DSA_65)))),
                        named("no algorithm attribute", List.of(unrelatedDefinition("context"))),
                        named("wrong algorithm UUID", List.of(wrongUuid)));
    }

    @ParameterizedTest(name = "{0}")
    @MethodSource("invalidSchemas")
    void expandSignatureAlgorithmDefinition_refusesInvalidOrConflictingDefinitions(List<BaseAttribute> schema,
            String expectedMessage) throws ConnectorException {
        // given
        List<BaseAttribute> connectorSchema = schema;

        // when
        Executable convert = () -> SignatureAlgorithmUtils.expandSignatureAlgorithmDefinition(connectorSchema);

        // then
        ConnectorException failure = assertThrows(ConnectorException.class, convert);
        assertEquals(expectedMessage, failure.getMessage());
    }

    private static Stream<Arguments> invalidSchemas() {
        DataAttributeV3 unknownCode = SignatureAlgorithmAttribute.definition(List.of());
        unknownCode.setContent(List.of(new StringAttributeContentV3("UNKNOWN")));
        DataAttributeV3 missingContent = SignatureAlgorithmAttribute.definition(List.of());
        missingContent.setContent(null);
        DataAttributeV3 numericCode = SignatureAlgorithmAttribute.definition(List.of());
        numericCode.setContent(List.of(new IntegerAttributeContentV3(256)));
        DataAttributeV3 conflictingUuid = unrelatedDefinition("connector-field");
        conflictingUuid.setUuid(RsaSignatureAttributes.ATTRIBUTE_DATA_RSA_SIG_SCHEME_UUID);
        String incompatibleChoices = "Connector signature algorithms do not share a common attribute representation.";
        String missingChoices = "Connector signatureAlgorithm definition must contain at least one algorithm code.";
        String conflictingFields = "Connector publishes conflicting signature attribute UUIDs or names.";
        return Stream
                .of(arguments(
                        named("RSA and ECDSA",
                                List
                                        .of(SignatureAlgorithmAttribute
                                                .definition(List
                                                        .of(SignatureAlgorithm.SHA256_WITH_RSA,
                                                                SignatureAlgorithm.SHA256_WITH_ECDSA)))),
                        incompatibleChoices),
                        arguments(
                                named("RSA and ML-DSA",
                                        List
                                                .of(SignatureAlgorithmAttribute
                                                        .definition(List
                                                                .of(SignatureAlgorithm.SHA256_WITH_RSA,
                                                                        SignatureAlgorithm.ML_DSA_65)))),
                                incompatibleChoices),
                        arguments(
                                named("ML-DSA and RSA",
                                        List
                                                .of(SignatureAlgorithmAttribute
                                                        .definition(List
                                                                .of(SignatureAlgorithm.ML_DSA_65,
                                                                        SignatureAlgorithm.SHA256_WITH_RSA)))),
                                incompatibleChoices),
                        arguments(named("unknown algorithm", List.of(unknownCode)),
                                "Connector signatureAlgorithm definition contains an unknown algorithm code."),
                        arguments(named("missing content", List.of(missingContent)),
                                "Connector signatureAlgorithm definition must contain a list of algorithm codes."),
                        arguments(named("empty algorithm choices",
                                List.of(SignatureAlgorithmAttribute.definition(List.of()))), missingChoices),
                        arguments(named("numeric algorithm code", List.of(numericCode)),
                                "Connector signatureAlgorithm choices must contain string algorithm codes."),
                        arguments(named("conflicting field name", List
                                .of(SignatureAlgorithmAttribute.definition(List.of(SignatureAlgorithm.SHA256_WITH_RSA)),
                                        unrelatedDefinition(RsaSignatureAttributes.ATTRIBUTE_DATA_SIG_DIGEST))),
                                conflictingFields),
                        arguments(named("conflicting field UUID", List
                                .of(SignatureAlgorithmAttribute.definition(List.of(SignatureAlgorithm.SHA256_WITH_RSA)),
                                        conflictingUuid)),
                                conflictingFields));
    }

    @Test
    void expandSignatureAlgorithmDefinition_refusesDuplicateSignatureAlgorithmDefinitions() throws ConnectorException {
        // given
        List<BaseAttribute> schema = List
                .of(SignatureAlgorithmAttribute.definition(List.of(SignatureAlgorithm.SHA256_WITH_RSA)),
                        SignatureAlgorithmAttribute.definition(List.of(SignatureAlgorithm.SHA384_WITH_RSA)));
        String expectedMessage = "Connector publishes more than one signatureAlgorithm attribute definition.";

        // when
        Executable convert = () -> SignatureAlgorithmUtils.expandSignatureAlgorithmDefinition(schema);

        // then
        ConnectorException failure = assertThrows(ConnectorException.class, convert);
        assertEquals(expectedMessage, failure.getMessage());
    }

    @Test
    void supportedAlgorithms_readsAllChoicesFromTheReservedDefinition_inOrder() throws ConnectorException {
        // given
        List<SignatureAlgorithm> expectedAlgorithms = List
                .of(SignatureAlgorithm.SHA256_WITH_RSA, SignatureAlgorithm.SHA384_WITH_RSA_PSS,
                        SignatureAlgorithm.SHA256_WITH_RSA);
        List<BaseAttribute> schema = List
                .of(unrelatedDefinition("context"), SignatureAlgorithmAttribute.definition(expectedAlgorithms));

        // when
        List<SignatureAlgorithm> algorithms = SignatureAlgorithmUtils.extractSupportedSignatureAlgorithms(schema);

        // then
        assertEquals(expectedAlgorithms, algorithms);
    }

    @ParameterizedTest(name = "{0}")
    @MethodSource("schemasOfferingNoAlgorithm")
    void supportedAlgorithms_returnsEmpty_whenThereAreNoOfferedAlgorithms(List<BaseAttribute> schema)
            throws ConnectorException {
        // given
        List<SignatureAlgorithm> expectedAlgorithms = List.of();

        // when
        List<SignatureAlgorithm> algorithms = SignatureAlgorithmUtils.extractSupportedSignatureAlgorithms(schema);

        // then
        assertEquals(expectedAlgorithms, algorithms);
    }

    private static Stream<Named<List<BaseAttribute>>> schemasOfferingNoAlgorithm() {
        DataAttributeV3 wrongUuid = SignatureAlgorithmAttribute.definition(List.of(SignatureAlgorithm.SHA256_WITH_RSA));
        wrongUuid.setUuid("ae2b12c7-8718-4cb4-a8ad-a34dbd48cfa2");
        return Stream
                .of(named("empty schema", List.of()),
                        named("only unrelated attributes", List.of(unrelatedDefinition("context"))),
                        named("wrong reserved UUID", List.of(wrongUuid)),
                        named("empty choice list", List.of(SignatureAlgorithmAttribute.definition(List.of()))));
    }

    @ParameterizedTest(name = "{0}")
    @MethodSource("invalidAlgorithmSchemas")
    void supportedAlgorithms_rejectsMalformedDefinitions_beforeReturningAnyChoices(List<BaseAttribute> schema,
            String expectedMessage) throws ConnectorException {
        // given
        List<BaseAttribute> connectorSchema = schema;

        // when
        Executable read = () -> SignatureAlgorithmUtils.extractSupportedSignatureAlgorithms(connectorSchema);

        // then
        ConnectorException failure = assertThrows(ConnectorException.class, read);
        assertEquals(expectedMessage, failure.getMessage());
    }

    private static Stream<Arguments> invalidAlgorithmSchemas() {
        DataAttributeV3 missingContent = SignatureAlgorithmAttribute.definition(List.of());
        missingContent.setContent(null);
        DataAttributeV3 numericCode = SignatureAlgorithmAttribute.definition(List.of());
        numericCode.setContent(List.of(new IntegerAttributeContentV3(256)));
        DataAttributeV3 unknownAfterValid = SignatureAlgorithmAttribute
                .definition(List.of(SignatureAlgorithm.SHA256_WITH_RSA));
        unknownAfterValid
                .setContent(List
                        .of(new StringAttributeContentV3(SignatureAlgorithm.SHA256_WITH_RSA.getCode()),
                                new StringAttributeContentV3("UNKNOWN")));
        return Stream
                .of(arguments(
                        named("duplicate definitions", List
                                .of(SignatureAlgorithmAttribute.definition(List.of(SignatureAlgorithm.SHA256_WITH_RSA)),
                                        SignatureAlgorithmAttribute
                                                .definition(List.of(SignatureAlgorithm.SHA384_WITH_RSA)))),
                        "Connector publishes more than one signatureAlgorithm attribute definition."),
                        arguments(named("missing content", List.of(missingContent)),
                                "Connector signatureAlgorithm definition must contain a list of algorithm codes."),
                        arguments(named("numeric algorithm code", List.of(numericCode)),
                                "Connector signatureAlgorithm choices must contain string algorithm codes."),
                        arguments(named("unknown code after valid choice", List.of(unknownAfterValid)),
                                "Connector signatureAlgorithm definition contains an unknown algorithm code."));
    }

    @Test
    void expandSignatureAlgorithmDefinition_returnsFreshDefinitionsAndOptions_onEachCall() throws ConnectorException {
        // given
        List<BaseAttribute> schema = List
                .of(SignatureAlgorithmAttribute.definition(List.of(SignatureAlgorithm.SHA256_WITH_RSA_PSS)));
        List<BaseAttribute> first = SignatureAlgorithmUtils.expandSignatureAlgorithmDefinition(schema);
        DataAttributeV3 changedScheme = (DataAttributeV3) first.getFirst();
        String changedLabel = "changed";
        String changedSchemeValue = "different-scheme";
        changedScheme.getProperties().setLabel(changedLabel);
        ((StringAttributeContentV3) changedScheme.getContent().getFirst()).setData(changedSchemeValue);

        // when
        List<BaseAttribute> next = SignatureAlgorithmUtils.expandSignatureAlgorithmDefinition(schema);

        // then
        assertEquals(RsaSignatureAttributes.ATTRIBUTE_DATA_RSA_SIG_SCHEME_LABEL,
                ((DataAttributeV3) next.getFirst()).getProperties().getLabel());
        assertEquals(List.of("PSS"), values(next.getFirst()));
    }

    private static void assertSplitDefinition(BaseAttribute attribute, String expectedUuid) throws ConnectorException {
        DataAttributeV3 definition = assertInstanceOf(DataAttributeV3.class, attribute);
        assertEquals(expectedUuid, definition.getUuid());
        assertEquals(3, definition.getVersion());
        assertEquals(AttributeContentType.STRING, definition.getContentType());
        assertTrue(definition.getProperties().isRequired());
        assertTrue(definition.getProperties().isVisible());
        assertTrue(definition.getProperties().isList());
        assertFalse(definition.getProperties().isMultiSelect());
        assertFalse(definition.getProperties().isReadOnly());
    }

    private static DataAttributeV3 unrelatedDefinition(String name) {
        DataAttributeV3 definition = new DataAttributeV3();
        definition.setUuid(UUID.randomUUID().toString());
        definition.setName(name);
        return definition;
    }

    private static List<String> names(List<BaseAttribute> definitions) {
        return definitions.stream().map(BaseAttribute::getName).toList();
    }

    private static List<String> values(BaseAttribute definition) {
        List<? extends AttributeContent> content = definition.getContent();
        return content.stream().map(item -> (String) item.getData()).toList();
    }
}
