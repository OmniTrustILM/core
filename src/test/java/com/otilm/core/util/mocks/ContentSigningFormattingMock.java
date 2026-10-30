package com.otilm.core.util.mocks;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonNode;
import com.github.tomakehurst.wiremock.client.WireMock;
import com.otilm.api.clients.signing.contentsigning.ContentSigningFormattingPaths;
import com.otilm.api.model.client.connector.v2.ConnectorInterface;
import com.otilm.api.model.client.connector.v2.FeatureFlag;
import com.otilm.api.model.common.attribute.common.content.AttributeContentType;
import com.otilm.api.model.common.attribute.common.properties.DataAttributeProperties;
import com.otilm.api.model.common.attribute.v2.DataAttributeV2;
import com.otilm.api.model.common.enums.cryptography.DigestAlgorithm;
import com.otilm.api.model.connector.signatures.contentsigning.common.ContentSigningFormattingOperation;
import com.otilm.api.model.connector.signatures.contentsigning.common.SignedDocumentResponseDto;
import com.otilm.api.model.connector.signatures.contentsigning.common.TimestampImprintResponseDto;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.UUID;

/**
 * Mock of a V2 content-signing formatting connector, backing {@code CONTENT_SIGNING} workflow profiles. Advertises
 * {@link FeatureFlag#CONTENT_SIGNING} on the four AdES family interfaces, plus
 * {@link ConnectorInterface#SIGNATURE_FORMATTING} for the legacy flat attributes route and the per-operation routes.
 */
public class ContentSigningFormattingMock extends BaseConnectorMock {

    private static final byte[] FOREIGN_DOCUMENT = "a different document".getBytes(StandardCharsets.UTF_8);

    ContentSigningFormattingMock() {
        super(new ComputeDtbsEchoTransformer(), new ComputeDtbsEchoTransformer(FOREIGN_DOCUMENT));
        advertiseFamilyInterfaces(List.of(FeatureFlag.CONTENT_SIGNING));
    }

    public ContentSigningFormattingMock advertiseTimestampedRung() {
        advertiseFamilyInterfaces(List.of(FeatureFlag.CONTENT_SIGNING, FeatureFlag.LEVEL_TIMESTAMPED));
        return this;
    }

    public ContentSigningFormattingMock advertiseNoContentSigningFeature() {
        advertiseFamilyInterfaces(List.of());
        return this;
    }

    private void advertiseFamilyInterfaces(List<FeatureFlag> familyFeatures) {
        stubV2InfoDetails(List
                .of(interfaceInfo(ConnectorInterface.INFO, List.of()),
                        interfaceInfo(ConnectorInterface.HEALTH, List.of()),
                        interfaceInfo(ConnectorInterface.METRICS, List.of()),
                        interfaceInfo(ConnectorInterface.SIGNATURE_FORMATTING, List.of()),
                        interfaceInfo(ConnectorInterface.PADES_FORMATTING, familyFeatures),
                        interfaceInfo(ConnectorInterface.XADES_FORMATTING, familyFeatures),
                        interfaceInfo(ConnectorInterface.CADES_FORMATTING, familyFeatures),
                        interfaceInfo(ConnectorInterface.JADES_FORMATTING, familyFeatures)));
    }

    public ContentSigningFormattingMock stubBaselineAndTimestampOperations() {
        stubComputeDtbs(ComputeDtbsEchoTransformer.NAME);
        stubOperation(ContentSigningFormattingOperation.EMBED_SIGNATURE_VALUE, signedDocumentJson("signed-document"));
        stubOperation(ContentSigningFormattingOperation.COMPUTE_SIGNATURE_TIMESTAMP_IMPRINT,
                timestampImprintJson(new byte[32]));
        stubOperation(ContentSigningFormattingOperation.EMBED_SIGNATURE_TIMESTAMP,
                signedDocumentJson("timestamped-document"));
        return this;
    }

    public ContentSigningFormattingMock stubComputeDtbsEchoingForeignDigest() {
        stubComputeDtbs(ComputeDtbsEchoTransformer.FOREIGN_NAME);
        return this;
    }

    private void stubComputeDtbs(String transformerName) {
        server
                .stubFor(WireMock
                        .post(WireMock
                                .urlPathMatching(".*" + ContentSigningFormattingPaths
                                        .operation(ContentSigningFormattingOperation.COMPUTE_DTBS)))
                        .willReturn(WireMock
                                .aResponse()
                                .withStatus(200)
                                .withHeader("Content-Type", "application/json")
                                .withTransformers(transformerName)));
    }

    private void stubOperation(ContentSigningFormattingOperation operation, String responseJson) {
        server
                .stubFor(WireMock
                        .post(WireMock.urlPathMatching(".*" + ContentSigningFormattingPaths.operation(operation)))
                        .willReturn(WireMock.okJson(responseJson)));
    }

    private static String signedDocumentJson(String content) {
        SignedDocumentResponseDto response = new SignedDocumentResponseDto();
        response.setSignedDocument(content.getBytes(StandardCharsets.UTF_8));
        return serialize(response, "signed document");
    }

    private static String timestampImprintJson(byte[] imprint) {
        TimestampImprintResponseDto response = new TimestampImprintResponseDto();
        response.setImprint(imprint);
        response.setDigestAlgorithm(DigestAlgorithm.SHA_256);
        return serialize(response, "timestamp imprint");
    }

    private static String serialize(Object response, String what) {
        try {
            return OBJECT_MAPPER.writeValueAsString(response);
        } catch (JsonProcessingException e) {
            throw new IllegalStateException("Failed to serialize " + what + " for WireMock stub", e);
        }
    }

    public ContentSigningFormattingMock stubFormattingAttributes() {
        server
                .stubFor(WireMock
                        .get(WireMock.urlPathMatching(".*/v1/signatureProvider/formatting/attributes"))
                        .willReturn(WireMock.okJson("[]")));
        return this;
    }

    public ContentSigningFormattingMock stubFormattingAttributeDefinition(UUID attrUuid, String attrName) {
        return stubFormattingAttributeDefinition(attrUuid, attrName, false);
    }

    public ContentSigningFormattingMock stubFormattingAttributeDefinition(UUID attrUuid, String attrName,
            boolean required) {
        try {
            server
                    .stubFor(WireMock
                            .get(WireMock.urlPathMatching(".*/v1/signatureProvider/formatting/attributes"))
                            .willReturn(WireMock
                                    .okJson(OBJECT_MAPPER
                                            .writeValueAsString(
                                                    List.of(attributeDefinition(attrUuid, attrName, required))))));
        } catch (JsonProcessingException e) {
            throw new RuntimeException("Failed to serialize attribute definition for WireMock stub", e);
        }
        return this;
    }

    public ContentSigningFormattingMock stubPerOperationFormattingAttributes() {
        for (ContentSigningFormattingOperation operation : ContentSigningFormattingOperation.values()) {
            server
                    .stubFor(WireMock
                            .get(WireMock.urlPathMatching(".*" + ContentSigningFormattingPaths.attributes(operation)))
                            .willReturn(WireMock.okJson("[]")));
        }
        return this;
    }

    public ContentSigningFormattingMock stubPerOperationFormattingAttributeDefinition(UUID attrUuid, String attrName) {
        return stubPerOperationFormattingAttributeDefinition(attrUuid, attrName, false);
    }

    public ContentSigningFormattingMock stubPerOperationFormattingAttributeDefinition(UUID attrUuid, String attrName,
            boolean required) {
        try {
            String body = OBJECT_MAPPER.writeValueAsString(List.of(attributeDefinition(attrUuid, attrName, required)));
            for (ContentSigningFormattingOperation operation : ContentSigningFormattingOperation.values()) {
                server
                        .stubFor(WireMock
                                .get(WireMock
                                        .urlPathMatching(".*" + ContentSigningFormattingPaths.attributes(operation)))
                                .willReturn(WireMock.okJson(body)));
            }
        } catch (JsonProcessingException e) {
            throw new RuntimeException("Failed to serialize attribute definition for WireMock stub", e);
        }
        return this;
    }

    /**
     * Declares one attribute on a single operation, so a caller can tell which operations an aggregate actually fetched
     * from the names it returns.
     */
    public ContentSigningFormattingMock stubFormattingAttributeDefinitionFor(
            ContentSigningFormattingOperation operation, UUID attrUuid, String attrName) {
        try {
            server
                    .stubFor(WireMock
                            .get(WireMock.urlPathMatching(".*" + ContentSigningFormattingPaths.attributes(operation)))
                            .willReturn(WireMock
                                    .okJson(OBJECT_MAPPER
                                            .writeValueAsString(
                                                    List.of(attributeDefinition(attrUuid, attrName, false))))));
        } catch (JsonProcessingException e) {
            throw new RuntimeException("Failed to serialize attribute definition for WireMock stub", e);
        }
        return this;
    }

    /**
     * The {@code signatureAlgorithm} each request to {@code operation} carried, in call order. An empty entry marks a
     * request that named none.
     */
    public List<String> signatureAlgorithmsReceivedBy(ContentSigningFormattingOperation operation) {
        return server
                .findAll(WireMock
                        .postRequestedFor(
                                WireMock.urlPathMatching(".*" + ContentSigningFormattingPaths.operation(operation))))
                .stream()
                .map(request -> signatureAlgorithmOf(request.getBodyAsString()))
                .toList();
    }

    private static String signatureAlgorithmOf(String body) {
        try {
            JsonNode algorithm = OBJECT_MAPPER.readTree(body).path("signatureAlgorithm");
            return algorithm.isTextual() ? algorithm.asText() : "";
        } catch (JsonProcessingException e) {
            throw new IllegalStateException("Recorded request body is not JSON", e);
        }
    }

    private static DataAttributeV2 attributeDefinition(UUID attrUuid, String attrName, boolean required) {
        DataAttributeV2 def = new DataAttributeV2();
        def.setUuid(attrUuid.toString());
        def.setName(attrName);
        def.setContentType(AttributeContentType.STRING);
        DataAttributeProperties props = new DataAttributeProperties();
        props.setLabel(attrName);
        props.setRequired(required);
        def.setProperties(props);
        return def;
    }
}
