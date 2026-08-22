package com.otilm.core.util.mocks;

import com.fasterxml.jackson.core.JsonProcessingException;
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
 * {@link ConnectorInterface#SIGNATURE_FORMATTING} for the legacy flat attributes route and the per-operation routes
 * stubbed below.
 */
public class ContentSigningFormattingMock extends BaseConnectorMock {

    private static final byte[] FOREIGN_DOCUMENT = "a different document".getBytes(StandardCharsets.UTF_8);

    ContentSigningFormattingMock() {
        super(new ComputeDtbsEchoTransformer(), new ComputeDtbsEchoTransformer(FOREIGN_DOCUMENT));
        advertiseFamilyInterfaces(List.of(FeatureFlag.CONTENT_SIGNING));
    }

    /**
     * Re-advertises the family interfaces with the {@code TIMESTAMPED} rung, which a profile whose ceiling is
     * {@code TIMESTAMPED} needs the connector to declare at save. Call before registering the connector, because that
     * is when the platform reads {@code /v2/info}.
     */
    public ContentSigningFormattingMock advertiseTimestampedRung() {
        advertiseFamilyInterfaces(List.of(FeatureFlag.CONTENT_SIGNING, FeatureFlag.LEVEL_TIMESTAMPED));
        return this;
    }

    /**
     * Re-advertises the family interfaces carrying no features, which is a formatting connector that cannot serve
     * content signing at all. Call before registering the connector, because that is when {@code /v2/info} is read.
     */
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

    /**
     * Stubs the operations a B+T run executes. {@code computeDtbs} echoes the SHA-256 of the document it was given, so
     * the platform's binding check sees a connector that committed to the authorized document.
     */
    public ContentSigningFormattingMock stubBaselineAndTimestampOperations() {
        stubComputeDtbs(ComputeDtbsEchoTransformer.NAME);
        stubOperation(ContentSigningFormattingOperation.EMBED_SIGNATURE_VALUE, signedDocumentJson("signed-document"));
        stubOperation(ContentSigningFormattingOperation.COMPUTE_SIGNATURE_TIMESTAMP_IMPRINT,
                timestampImprintJson(new byte[32]));
        stubOperation(ContentSigningFormattingOperation.EMBED_SIGNATURE_TIMESTAMP,
                signedDocumentJson("timestamped-document"));
        return this;
    }

    /** Echoes a digest of different content, so the binding check has a mismatch to catch. */
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

    /**
     * Stubs the signature-formatting attributes endpoint to advertise a single optional STRING attribute definition.
     * Takes precedence over {@link #stubFormattingAttributes()} when called after it.
     */
    public ContentSigningFormattingMock stubFormattingAttributeDefinition(UUID attrUuid, String attrName) {
        return stubFormattingAttributeDefinition(attrUuid, attrName, false);
    }

    /**
     * Stubs the signature-formatting attributes endpoint to advertise a single STRING attribute definition. When
     * {@code required=true}, the service must reject requests that omit this attribute. Takes precedence over
     * {@link #stubFormattingAttributes()} when called after it.
     */
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

    /** Stubs every per-operation attribute route the AdES content-signing client calls to advertise no attributes. */
    public ContentSigningFormattingMock stubPerOperationFormattingAttributes() {
        for (ContentSigningFormattingOperation operation : ContentSigningFormattingOperation.values()) {
            server
                    .stubFor(WireMock
                            .get(WireMock.urlPathMatching(".*" + ContentSigningFormattingPaths.attributes(operation)))
                            .willReturn(WireMock.okJson("[]")));
        }
        return this;
    }

    /**
     * Stubs every per-operation attribute route to advertise the same single optional STRING attribute definition,
     * mirroring {@link #stubFormattingAttributeDefinition(UUID, String)} for the per-operation contract.
     */
    public ContentSigningFormattingMock stubPerOperationFormattingAttributeDefinition(UUID attrUuid, String attrName) {
        return stubPerOperationFormattingAttributeDefinition(attrUuid, attrName, false);
    }

    /**
     * Stubs every per-operation attribute route to advertise the same single STRING attribute definition. When
     * {@code required=true}, the service must reject requests that omit this attribute.
     */
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
