package com.otilm.core.attribute;

import com.otilm.api.exception.ValidationException;
import com.otilm.api.model.client.attribute.RequestAttribute;
import com.otilm.api.model.client.attribute.RequestAttributeV3;
import com.otilm.api.model.common.attribute.common.content.AttributeContentType;
import com.otilm.api.model.common.attribute.v3.content.StringAttributeContentV3;
import com.otilm.api.model.common.enums.cryptography.DigestAlgorithm;
import com.otilm.api.model.common.enums.cryptography.RsaSignatureScheme;
import com.otilm.api.model.common.enums.cryptography.SignatureAlgorithm;
import com.otilm.api.model.connector.cryptography.v2.operations.SignatureAlgorithmAttribute;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.UUID;
import java.util.stream.Stream;
import org.junit.jupiter.api.Named;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.function.Executable;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;
import org.junit.jupiter.params.provider.MethodSource;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Named.named;

class SignatureOperationAttributesTest {

    @Test
    void toConnector_replacesSplitFields_andPreservesOtherParametersAndInput() {
        // given
        RequestAttribute parameter = connectorParameter();
        RequestAttribute scheme = RsaSignatureAttributes.buildRequestRsaSigScheme(RsaSignatureScheme.PSS);
        RequestAttribute digest = RsaSignatureAttributes.buildRequestDigest(DigestAlgorithm.SHA_384);
        List<RequestAttribute> submitted = List.of(scheme, parameter, digest);

        // when
        List<RequestAttribute> translated = SignatureOperationAttributes.toConnector(submitted);

        // then
        assertEquals(List.of(parameter.getName(), SignatureAlgorithmAttribute.NAME),
                translated.stream().map(RequestAttribute::getName).toList());
        assertSame(parameter, translated.getFirst());
        assertEquals(SignatureAlgorithm.SHA384_WITH_RSA_PSS, SignatureAlgorithmAttribute.selectedAlgorithm(translated));
        assertEquals(List.of(scheme, parameter, digest), submitted);
    }

    @ParameterizedTest
    @EnumSource(SignatureAlgorithm.class)
    void toConnector_sendsOneV3Selector_forEveryMappedOrOriginalAlgorithm(SignatureAlgorithm algorithm) {
        // given
        List<RequestAttribute> submitted = SignatureAlgorithmMapping.toAttributes(algorithm);

        // when
        List<RequestAttribute> translated = SignatureOperationAttributes.toConnector(submitted);

        // then
        assertEquals(1, translated.size());
        assertInstanceOf(RequestAttributeV3.class, translated.getFirst());
        assertEquals(algorithm, SignatureAlgorithmAttribute.selectedAlgorithm(translated));
    }

    @Test
    void toConnector_preservesParameters_besideOriginalAlgorithmSelector() {
        // given
        RequestAttribute parameter = connectorParameter();
        List<RequestAttribute> submitted = List
                .of(parameter, SignatureAlgorithmAttribute.request(SignatureAlgorithm.ML_DSA_65));

        // when
        List<RequestAttribute> translated = SignatureOperationAttributes.toConnector(submitted);

        // then
        assertSame(parameter, translated.getFirst());
        assertEquals(SignatureAlgorithm.ML_DSA_65, SignatureAlgorithmAttribute.selectedAlgorithm(translated));
    }

    @Test
    void toConnector_leavesMissingAlgorithmSelection_forConnectorSchemaValidation() {
        // given
        List<RequestAttribute> submitted = List.of(connectorParameter());

        // when
        List<RequestAttribute> translated = SignatureOperationAttributes.toConnector(submitted);

        // then
        assertSame(submitted, translated);
    }

    @ParameterizedTest
    @EnumSource(SignatureAlgorithm.class)
    void resolveAlgorithm_ignoresOtherConnectorParameters(SignatureAlgorithm expectedAlgorithm) {
        // given
        List<RequestAttribute> submitted = new ArrayList<>(SignatureAlgorithmMapping.toAttributes(expectedAlgorithm));
        submitted.add(connectorParameter());

        // when
        SignatureAlgorithm algorithm = SignatureOperationAttributes.resolveAlgorithm(submitted);

        // then
        assertEquals(expectedAlgorithm, algorithm);
    }

    @ParameterizedTest(name = "{0}")
    @MethodSource("invalidSelections")
    void toConnector_refusesInvalidAlgorithmSelections(List<RequestAttribute> submitted) {
        // given
        List<RequestAttribute> attributes = submitted;

        // when
        Executable translate = () -> SignatureOperationAttributes.toConnector(attributes);

        // then
        assertThrows(ValidationException.class, translate);
    }

    @ParameterizedTest(name = "{0}")
    @MethodSource("invalidSelections")
    void resolveAlgorithm_refusesInvalidSelections(List<RequestAttribute> submitted) {
        // given
        List<RequestAttribute> attributes = submitted;

        // when
        Executable resolve = () -> SignatureOperationAttributes.resolveAlgorithm(attributes);

        // then
        assertThrows(ValidationException.class, resolve);
    }

    @Test
    void resolveAlgorithm_refusesMissingAlgorithmSelection() {
        // given
        List<RequestAttribute> submitted = List.of(connectorParameter());

        // when
        Executable resolve = () -> SignatureOperationAttributes.resolveAlgorithm(submitted);

        // then
        assertThrows(ValidationException.class, resolve);
    }

    private static Stream<Named<List<RequestAttribute>>> invalidSelections() {
        RequestAttribute scheme = RsaSignatureAttributes.buildRequestRsaSigScheme(RsaSignatureScheme.PSS);
        RequestAttribute digest = RsaSignatureAttributes.buildRequestDigest(DigestAlgorithm.SHA_256);
        RequestAttributeV3 missingUuid = new RequestAttributeV3(null, RsaSignatureAttributes.ATTRIBUTE_DATA_SIG_DIGEST,
                AttributeContentType.STRING, List.of(new StringAttributeContentV3(DigestAlgorithm.SHA_256.getCode())));
        return Stream
                .of(named("missing digest", List.of(scheme)), named("duplicate digest", List.of(digest, digest)),
                        named("original selector mixed with split field", List
                                .of(SignatureAlgorithmAttribute.request(SignatureAlgorithm.SHA256_WITH_RSA), digest)),
                        named("missing attribute UUID", List.of(missingUuid)),
                        named("null attribute", Collections.singletonList(null)));
    }

    private static RequestAttribute connectorParameter() {
        String parameterName = "signatureContext";
        String parameterValue = "context-value";
        return new RequestAttributeV3(UUID.randomUUID(), parameterName, AttributeContentType.STRING,
                List.of(new StringAttributeContentV3(parameterValue)));
    }
}
