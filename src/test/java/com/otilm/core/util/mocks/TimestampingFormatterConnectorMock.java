package com.otilm.core.util.mocks;

import com.otilm.api.model.client.connector.v2.ConnectorInterface;
import com.otilm.api.model.client.connector.v2.FeatureFlag;
import com.otilm.api.model.common.attribute.common.content.AttributeContentType;
import com.otilm.api.model.common.attribute.common.properties.DataAttributeProperties;
import com.otilm.api.model.common.attribute.v2.DataAttributeV2;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.github.tomakehurst.wiremock.client.WireMock;

import java.util.Base64;
import java.util.List;
import java.util.UUID;

/**
 * Mock of a V2 timestamping formatter connector — stubs {@code GET /v2/info} advertising
 * {@link ConnectorInterface#SIGNATURE_FORMATTING} with {@link FeatureFlag#TIMESTAMPING}.
 * Used to back {@code TIMESTAMPING} workflow profiles.
 *
 * <p>Beyond discovery, {@link #stubFormatDtbs()} and {@link #stubFormatResponse()} implement the
 * runtime two-round-trip RFC 3161 formatter contract for real: phase 1 returns the genuine CMS
 * data-to-be-signed for the request's TSTInfo, and phase 2 assembles a real {@code TimeStampToken}
 * embedding the externally produced signature — so tokens it produces verify against the signer
 * certificate.
 */
public class TimestampingFormatterConnectorMock extends BaseConnectorMock {

    TimestampingFormatterConnectorMock() {
        super(new TimestampingFormatDtbsTransformer(), new TimestampingFormatResponseTransformer());
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

    /**
     * Stubs phase 1 of the RFC 3161 formatter contract ({@code formatDtbs}) — see
     * {@link TimestampingFormatDtbsTransformer}.
     */
    public TimestampingFormatterConnectorMock stubFormatDtbs() {
        server.stubFor(WireMock.post(WireMock.urlPathMatching(".*/v1/signatureProvider/formatting/formatDtbs"))
                .willReturn(WireMock.aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/json")
                        .withTransformers(TimestampingFormatDtbsTransformer.NAME)));
        return this;
    }

    /**
     * Stubs phase 2 of the RFC 3161 formatter contract ({@code formatResponse}) — see
     * {@link TimestampingFormatResponseTransformer}.
     */
    public TimestampingFormatterConnectorMock stubFormatResponse() {
        server.stubFor(WireMock.post(WireMock.urlPathMatching(".*/v1/signatureProvider/formatting/formatResponse"))
                .willReturn(WireMock.aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/json")
                        .withTransformers(TimestampingFormatResponseTransformer.NAME)));
        return this;
    }

    /**
     * Stubs the two-phase timestamp assembly with fixed, request-agnostic responses: {@code formatDtbs}
     * returns placeholder data-to-be-signed, and {@code formatResponse} returns the given pre-built RFC 3161
     * token bytes verbatim. Unlike {@link #stubFormatDtbs()}/{@link #stubFormatResponse()} (which assemble a
     * token derived from the request and therefore require a fully-populated request, e.g. a policy OID), this
     * returns a caller-supplied token regardless of request content — suited to minimal-request unit tests.
     * The token must be structurally parseable as a CMS {@code TimeStampToken}; it need not cryptographically
     * verify unless the profile enables token-signature validation.
     */
    public TimestampingFormatterConnectorMock stubTokenAssembly(byte[] timestampTokenBytes) {
        String dtbs = Base64.getEncoder().encodeToString("placeholder-dtbs".getBytes());
        String token = Base64.getEncoder().encodeToString(timestampTokenBytes);
        server.stubFor(WireMock.post(WireMock.urlPathMatching(".*/v1/signatureProvider/formatting/formatDtbs"))
                .willReturn(WireMock.okJson("{\"dtbs\":\"" + dtbs + "\"}")));
        server.stubFor(WireMock.post(WireMock.urlPathMatching(".*/v1/signatureProvider/formatting/formatResponse"))
                .willReturn(WireMock.okJson("{\"response\":\"" + token + "\"}")));
        return this;
    }

    /**
     * Stubs the {@code formatDtbs} phase to fail, so the engine surfaces a {@code SYSTEM_FAILURE} rejection.
     */
    public TimestampingFormatterConnectorMock stubTokenAssemblyFailure() {
        server.stubFor(WireMock.post(WireMock.urlPathMatching(".*/v1/signatureProvider/formatting/formatDtbs"))
                .willReturn(WireMock.serverError()));
        return this;
    }
}
