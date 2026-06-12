package com.otilm.core.util.mocks;

import com.otilm.api.model.client.connector.v2.ConnectorInterface;
import com.otilm.api.model.client.connector.v2.ConnectorInterfaceInfo;
import com.otilm.api.model.client.connector.v2.FeatureFlag;
import com.otilm.api.model.client.connector.v2.InfoResponse;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.github.tomakehurst.wiremock.WireMockServer;
import com.github.tomakehurst.wiremock.client.WireMock;
import com.github.tomakehurst.wiremock.core.WireMockConfiguration;
import com.github.tomakehurst.wiremock.extension.Extension;

import java.util.List;

import static com.otilm.core.util.builders.ConnectorInfoBuilder.aConnectorInfo;

/**
 * Base for WireMock servers that impersonate an OTILM connector.
 * <p>
 * Owns the WireMock server lifecycle and the generic discovery stubs shared by every connector flavour:
 * {@code GET /v1} (V1 function-group discovery) and {@code GET /v2/info} (V2 interface discovery).
 * Concrete subclasses (e.g. {@link TimestampingFormatterConnectorMock}, {@link CryptographyProviderConnectorMock})
 * add the function-specific stubs in their constructor.
 * Instances are created exclusively through {@link ConnectorMockFactory}, which injects any Spring beans
 * a mock needs at start. Call {@link #stop()} in {@code @AfterEach}.
 */
public abstract class BaseConnectorMock {

    protected static final ObjectMapper OBJECT_MAPPER = new ObjectMapper();

    protected final WireMockServer server;

    protected BaseConnectorMock() {
        this.server = new WireMockServer(0);
        this.server.start();
    }

    /**
     * Variant for mocks whose responses are computed per request (e.g. real signing or token assembly):
     * WireMock response transformers can only be registered at server creation time.
     */
    protected BaseConnectorMock(Extension... extensions) {
        this.server = new WireMockServer(WireMockConfiguration.options().port(0).extensions(extensions));
        this.server.start();
    }

    protected static ConnectorInterfaceInfo interfaceInfo(ConnectorInterface code, List<FeatureFlag> features) {
        ConnectorInterfaceInfo info = new ConnectorInterfaceInfo();
        info.setCode(code);
        info.setVersion("v2");
        info.setFeatures(features);
        return info;
    }

    public String getUrl() {
        return "http://localhost:" + server.port();
    }

    public void stop() {
        server.stop();
    }

    /**
     * Stubs {@code GET /v1} — the V1 connector validation endpoint — with the given function groups.
     */
    protected void stubV1FunctionGroups(List<com.otilm.api.model.client.connector.InfoResponse> functions) {
        try {
            server.stubFor(WireMock.get("/v1")
                    .willReturn(WireMock.okJson(OBJECT_MAPPER.writeValueAsString(functions))));
        } catch (JsonProcessingException e) {
            throw new RuntimeException("Failed to serialize V1 function groups for WireMock stub", e);
        }
    }

    /**
     * Stubs {@code GET /v2/info} — the V2 connector validation endpoint — with the given interfaces
     * (no feature flags on any interface).
     */
    protected void stubV2Info(List<ConnectorInterface> interfaces) {
        List<ConnectorInterfaceInfo> infos = interfaces.stream()
                .map(iface -> {
                    ConnectorInterfaceInfo info = new ConnectorInterfaceInfo();
                    info.setCode(iface);
                    info.setVersion("v2");
                    info.setFeatures(List.of());
                    return info;
                })
                .toList();
        stubV2InfoDetails(infos);
    }

    /**
     * Stubs {@code GET /v2/info} with fully-specified {@link ConnectorInterfaceInfo} entries,
     * allowing callers to declare per-interface feature flags.
     */
    protected void stubV2InfoDetails(List<ConnectorInterfaceInfo> interfaces) {
        InfoResponse infoResponse = new InfoResponse();
        infoResponse.setConnector(aConnectorInfo().build());
        infoResponse.setInterfaces(interfaces);

        try {
            server.stubFor(WireMock.get("/v2/info")
                    .willReturn(WireMock.okJson(OBJECT_MAPPER.writeValueAsString(infoResponse))));
        } catch (JsonProcessingException e) {
            throw new RuntimeException("Failed to serialize InfoResponse for WireMock stub", e);
        }
    }
}
