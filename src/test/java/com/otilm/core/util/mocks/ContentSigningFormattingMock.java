package com.otilm.core.util.mocks;

import com.otilm.api.model.client.connector.v2.ConnectorInterface;
import com.otilm.api.model.client.connector.v2.FeatureFlag;
import com.otilm.api.model.common.attribute.common.content.AttributeContentType;
import com.otilm.api.model.common.attribute.common.properties.DataAttributeProperties;
import com.otilm.api.model.common.attribute.v2.DataAttributeV2;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.github.tomakehurst.wiremock.client.WireMock;

import java.util.List;
import java.util.UUID;

/**
 * Mock of a V2 content-signing formatting connector — stubs {@code GET /v2/info} advertising
 * {@link ConnectorInterface#SIGNATURE_FORMATTING} with {@link FeatureFlag#CONTENT_SIGNING}.
 * Used to back {@code CONTENT_SIGNING} workflow profiles.
 */
public class ContentSigningFormattingMock extends BaseConnectorMock {

    ContentSigningFormattingMock() {
        stubV2InfoDetails(List.of(
                interfaceInfo(ConnectorInterface.INFO, List.of()),
                interfaceInfo(ConnectorInterface.HEALTH, List.of()),
                interfaceInfo(ConnectorInterface.METRICS, List.of()),
                interfaceInfo(ConnectorInterface.SIGNING, List.of()),
                interfaceInfo(ConnectorInterface.SIGNATURE_FORMATTING, List.of(FeatureFlag.CONTENT_SIGNING))
        ));
    }

    public ContentSigningFormattingMock stubFormattingAttributes() {
        server.stubFor(WireMock.get(WireMock.urlPathMatching(".*/v1/signatureProvider/formatting/attributes"))
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
     * Stubs the signature-formatting attributes endpoint to advertise a single STRING attribute definition.
     * When {@code required=true}, the service must reject requests that omit this attribute.
     * Takes precedence over {@link #stubFormattingAttributes()} when called after it.
     */
    public ContentSigningFormattingMock stubFormattingAttributeDefinition(UUID attrUuid, String attrName, boolean required) {
        DataAttributeV2 def = new DataAttributeV2();
        def.setUuid(attrUuid.toString());
        def.setName(attrName);
        def.setContentType(AttributeContentType.STRING);
        DataAttributeProperties props = new DataAttributeProperties();
        props.setLabel(attrName);
        props.setRequired(required);
        def.setProperties(props);
        try {
            server.stubFor(WireMock.get(WireMock.urlPathMatching(".*/v1/signatureProvider/formatting/attributes"))
                    .willReturn(WireMock.okJson(OBJECT_MAPPER.writeValueAsString(List.of(def)))));
        } catch (JsonProcessingException e) {
            throw new RuntimeException("Failed to serialize attribute definition for WireMock stub", e);
        }
        return this;
    }
}
