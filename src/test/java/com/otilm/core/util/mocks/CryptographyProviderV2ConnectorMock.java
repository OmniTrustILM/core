package com.otilm.core.util.mocks;

import com.github.tomakehurst.wiremock.client.WireMock;
import com.otilm.api.model.client.connector.v2.ConnectorInterface;
import java.util.List;

import static com.github.tomakehurst.wiremock.client.WireMock.postRequestedFor;

/** WireMock connector for the stateless cryptography-provider v2 token API. */
public class CryptographyProviderV2ConnectorMock extends BaseConnectorMock {

    CryptographyProviderV2ConnectorMock() {
        stubV2Info(List.of(ConnectorInterface.CRYPTOGRAPHY));
    }

    public CryptographyProviderV2ConnectorMock stubTokenAttributes(String responseJson) {
        server
                .stubFor(WireMock
                        .get(WireMock.urlPathEqualTo("/v2/cryptographyProvider/tokens/attributes"))
                        .willReturn(WireMock.okJson(responseJson)));
        return this;
    }

    public CryptographyProviderV2ConnectorMock stubTokenStatus(String responseJson) {
        server
                .stubFor(WireMock
                        .post(WireMock.urlPathEqualTo("/v2/cryptographyProvider/tokens/status"))
                        .willReturn(WireMock.okJson(responseJson)));
        return this;
    }

    public CryptographyProviderV2ConnectorMock stubTokenStatusWithAttributes(String responseJson,
            String expectedRequestJson) {
        server
                .stubFor(WireMock
                        .post(WireMock.urlPathEqualTo("/v2/cryptographyProvider/tokens/status"))
                        .withRequestBody(WireMock.equalToJson(expectedRequestJson))
                        .willReturn(WireMock.okJson(responseJson)));
        return this;
    }

    public CryptographyProviderV2ConnectorMock stubTokenStatusContainingAttribute(String responseJson,
            String attributeName, String attributeValue) {
        server
                .stubFor(WireMock
                        .post(WireMock.urlPathEqualTo("/v2/cryptographyProvider/tokens/status"))
                        .withRequestBody(
                                WireMock.matchingJsonPath("$.tokenAttributes[0].name", WireMock.equalTo(attributeName)))
                        .withRequestBody(WireMock
                                .matchingJsonPath("$.tokenAttributes[0].content[0].data",
                                        WireMock.equalTo(attributeValue)))
                        .willReturn(WireMock.okJson(responseJson)));
        return this;
    }

    public CryptographyProviderV2ConnectorMock stubTokenProfileAttributes(String responseJson) {
        server
                .stubFor(WireMock
                        .post(WireMock.urlPathEqualTo("/v2/cryptographyProvider/tokens/tokenProfile/attributes"))
                        .willReturn(WireMock.okJson(responseJson)));
        return this;
    }

    public CryptographyProviderV2ConnectorMock stubTokenProfileKeyUsages(String responseJson) {
        server
                .stubFor(WireMock
                        .post(WireMock.urlPathEqualTo("/v2/cryptographyProvider/tokens/tokenProfile/keyUsages"))
                        .willReturn(WireMock.okJson(responseJson)));
        return this;
    }

    public CryptographyProviderV2ConnectorMock stubTokenProfileKeyUsagesWithoutBody() {
        server
                .stubFor(WireMock
                        .post(WireMock.urlPathEqualTo("/v2/cryptographyProvider/tokens/tokenProfile/keyUsages"))
                        .willReturn(WireMock.ok()));
        return this;
    }

    public CryptographyProviderV2ConnectorMock stubTokenProfileKeyUsagesError() {
        server
                .stubFor(WireMock
                        .post(WireMock.urlPathEqualTo("/v2/cryptographyProvider/tokens/tokenProfile/keyUsages"))
                        .willReturn(WireMock.serverError()));
        return this;
    }

    public CryptographyProviderV2ConnectorMock stubTokenOperations() {
        return stubTokenAttributes("[]").stubTokenStatus("{\"status\":\"Connected\"}").stubTokenProfileAttributes("[]");
    }

    public void verifyTokenAttributesRequest() {
        server.verify(WireMock.getRequestedFor(WireMock.urlPathEqualTo("/v2/cryptographyProvider/tokens/attributes")));
    }

    public void verifyTokenProfileAttributesRequest() {
        server
                .verify(postRequestedFor(
                        WireMock.urlPathEqualTo("/v2/cryptographyProvider/tokens/tokenProfile/attributes")));
    }

    public void verifyScopedTokenProfileAttributesRequest(String expectedRequestJson) {
        server
                .verify(postRequestedFor(
                        WireMock.urlPathEqualTo("/v2/cryptographyProvider/tokens/tokenProfile/attributes"))
                        .withRequestBody(WireMock.equalToJson(expectedRequestJson)));
    }

    public void verifyScopedTokenProfileAttributesRequestContaining(String expectedRequestJson) {
        server
                .verify(postRequestedFor(
                        WireMock.urlPathEqualTo("/v2/cryptographyProvider/tokens/tokenProfile/attributes"))
                        .withRequestBody(WireMock.equalToJson(expectedRequestJson, true, true)));
    }

    public void verifyScopedTokenProfileKeyUsagesRequest(String expectedRequestJson) {
        server
                .verify(postRequestedFor(
                        WireMock.urlPathEqualTo("/v2/cryptographyProvider/tokens/tokenProfile/keyUsages"))
                        .withRequestBody(WireMock.equalToJson(expectedRequestJson)));
    }

    public void verifyScopedTokenProfileKeyUsagesRequestContaining(String expectedRequestJson) {
        server
                .verify(postRequestedFor(
                        WireMock.urlPathEqualTo("/v2/cryptographyProvider/tokens/tokenProfile/keyUsages"))
                        .withRequestBody(WireMock.equalToJson(expectedRequestJson, true, true)));
    }

    public void verifyScopedTokenStatusRequest(String expectedRequestJson) {
        server
                .verify(postRequestedFor(WireMock.urlPathEqualTo("/v2/cryptographyProvider/tokens/status"))
                        .withRequestBody(WireMock.equalToJson(expectedRequestJson)));
    }

    public void verifyScopedTokenStatusRequestContaining(String expectedRequestJson) {
        server
                .verify(postRequestedFor(WireMock.urlPathEqualTo("/v2/cryptographyProvider/tokens/status"))
                        .withRequestBody(WireMock.equalToJson(expectedRequestJson, true, true)));
    }
}
