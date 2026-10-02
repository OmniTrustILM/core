package com.otilm.core.attribute;

import com.otilm.api.exception.ValidationException;
import com.otilm.api.model.client.attribute.RequestAttribute;
import com.otilm.api.model.client.attribute.RequestAttributeV3;
import com.otilm.api.model.common.enums.cryptography.EncryptionAlgorithm;
import com.otilm.api.model.connector.cryptography.v2.operations.EncryptionAlgorithmAttribute;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.UUID;
import java.util.stream.Stream;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.function.Executable;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;
import org.junit.jupiter.params.provider.MethodSource;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;

class EncryptionOperationAttributesTest {

    @ParameterizedTest
    @EnumSource(EncryptionAlgorithm.class)
    void toConnector_convertsSplitSelection_preservingOtherAttributesAndInput(EncryptionAlgorithm algorithm) {
        // given
        RequestAttribute extra = unrelatedAttribute();
        List<RequestAttribute> submitted = new ArrayList<>(EncryptionAlgorithmMapping.toAttributes(algorithm));
        submitted.add(extra);
        List<RequestAttribute> original = List.copyOf(submitted);

        // when
        List<RequestAttribute> converted = EncryptionOperationAttributes.toConnector(submitted);

        // then
        assertEquals(2, converted.size());
        assertSame(extra, converted.getFirst());
        assertEquals(algorithm, EncryptionAlgorithmAttribute.selectedAlgorithm(List.of(converted.getLast())));
        assertEquals(original, submitted);
    }

    @ParameterizedTest
    @EnumSource(EncryptionAlgorithm.class)
    void toConnector_acceptsOriginalSelector(EncryptionAlgorithm algorithm) {
        // given
        List<RequestAttribute> submitted = List.of(EncryptionAlgorithmAttribute.request(algorithm));

        // when
        List<RequestAttribute> converted = EncryptionOperationAttributes.toConnector(submitted);

        // then
        assertEquals(algorithm, EncryptionAlgorithmAttribute.selectedAlgorithm(converted));
    }

    @Test
    void toConnector_preservesAttributes_whenSelectionIsOmitted() {
        // given
        List<RequestAttribute> submitted = List.of(unrelatedAttribute());

        // when
        List<RequestAttribute> converted = EncryptionOperationAttributes.toConnector(submitted);

        // then
        assertSame(submitted, converted);
    }

    @ParameterizedTest
    @MethodSource("invalidSelections")
    void toConnector_rejectsMalformedOrMixedSelection(List<RequestAttribute> submitted) {
        // given
        Class<ValidationException> expectedFailure = ValidationException.class;

        // when
        Executable convert = () -> EncryptionOperationAttributes.toConnector(submitted);

        // then
        assertThrows(expectedFailure, convert);
    }

    private static Stream<List<RequestAttribute>> invalidSelections() {
        List<RequestAttribute> mixed = new ArrayList<>(
                EncryptionAlgorithmMapping.toAttributes(EncryptionAlgorithm.RSA_OAEP_SHA256));
        mixed.add(EncryptionAlgorithmAttribute.request(EncryptionAlgorithm.RSA_OAEP_SHA256));
        List<RequestAttribute> incomplete = EncryptionAlgorithmMapping
                .toAttributes(EncryptionAlgorithm.RSA_OAEP_SHA256)
                .subList(0, 2);
        RequestAttributeV3 wrongUuid = (RequestAttributeV3) EncryptionAlgorithmMapping
                .toAttributes(EncryptionAlgorithm.RSA_PKCS1_V1_5)
                .getFirst();
        wrongUuid.setUuid(UUID.randomUUID());
        RequestAttributeV3 wrongName = (RequestAttributeV3) EncryptionAlgorithmMapping
                .toAttributes(EncryptionAlgorithm.RSA_PKCS1_V1_5)
                .getFirst();
        wrongName.setName("wrong-name");
        return Stream
                .of(mixed, incomplete, List.of(wrongUuid), List.of(wrongName), Arrays.asList((RequestAttribute) null));
    }

    private static RequestAttribute unrelatedAttribute() {
        RequestAttributeV3 attribute = new RequestAttributeV3();
        attribute.setUuid(UUID.randomUUID());
        attribute.setName("connector-option");
        return attribute;
    }
}
