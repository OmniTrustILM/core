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
 * Mock of a V2 timestamping formatter connector — stubs {@code GET /v2/info} advertising
 * {@link ConnectorInterface#SIGNATURE_FORMATTING} with {@link FeatureFlag#TIMESTAMPING}.
 * Used to back {@code TIMESTAMPING} workflow profiles.
 */
public class TimestampingFormatterConnectorMock extends BaseConnectorMock {

    TimestampingFormatterConnectorMock() {
        stubV2InfoDetails(List.of(
                interfaceInfo(ConnectorInterface.INFO, List.of()),
                interfaceInfo(ConnectorInterface.HEALTH, List.of()),
                interfaceInfo(ConnectorInterface.METRICS, List.of()),
                interfaceInfo(ConnectorInterface.SIGNING, List.of()),
                interfaceInfo(ConnectorInterface.SIGNATURE_FORMATTING, List.of(FeatureFlag.TIMESTAMPING))
        ));
    }

    /**
     * Stubs the signature-formatter attributes endpoint to advertise no attributes (empty list).
     */
    public TimestampingFormatterConnectorMock stubFormatterAttributes() {
        server.stubFor(WireMock.get(WireMock.urlPathMatching(".*/v1/signatureProvider/formatting/attributes"))
                .willReturn(WireMock.okJson("[]")));
        return this;
    }

    /**
     * Stubs the signature-formatter attributes endpoint to advertise a single STRING attribute definition.
     * Takes precedence over {@link #stubFormatterAttributes()} when called after it.
     */
    public TimestampingFormatterConnectorMock stubFormatterAttributeDefinition(UUID attrUuid, String attrName, boolean required) {
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
