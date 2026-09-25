package com.otilm.core.util.mocks;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.github.tomakehurst.wiremock.client.WireMock;
import com.github.tomakehurst.wiremock.http.Fault;
import com.otilm.api.model.client.connector.v2.ConnectorInterface;
import com.otilm.api.model.client.cryptography.key.KeyRequestType;
import com.otilm.api.model.common.enums.cryptography.KeyAlgorithm;
import com.otilm.api.model.connector.cryptography.v2.key.ExportableKeyTypeV2Dto;
import com.otilm.core.serialization.ObjectMapperFactory;
import java.util.List;
import java.util.Set;

import static com.github.tomakehurst.wiremock.client.WireMock.postRequestedFor;

/** WireMock connector for the stateless cryptography-provider v2 token and operations APIs. */
public class CryptographyProviderV2ConnectorMock extends BaseConnectorMock {

    private static final String OPERATIONS = "/v2/cryptographyProvider/operations/";
    private static final String EXPORTABLE_KEY_TYPES = "/v2/cryptographyProvider/keys/export/keyTypes";

    CryptographyProviderV2ConnectorMock() {
        stubV2Info(List.of(ConnectorInterface.CRYPTOGRAPHY));
    }

    public CryptographyProviderV2ConnectorMock stubOperationAttributes(String operation, String responseJson) {
        server
                .stubFor(WireMock
                        .post(WireMock.urlPathEqualTo(OPERATIONS + operation + "/attributes"))
                        .willReturn(WireMock.okJson(responseJson)));
        return this;
    }

    public CryptographyProviderV2ConnectorMock stubOperation(String operation, String responseJson) {
        server
                .stubFor(WireMock
                        .post(WireMock.urlPathEqualTo(OPERATIONS + operation))
                        .willReturn(WireMock.okJson(responseJson)));
        return this;
    }

    public CryptographyProviderV2ConnectorMock stubOperationAccepted(String operation, String responseJson) {
        server
                .stubFor(WireMock
                        .post(WireMock.urlPathEqualTo(OPERATIONS + operation))
                        .willReturn(WireMock.jsonResponse(responseJson, 202)));
        return this;
    }

    public CryptographyProviderV2ConnectorMock stubOperationError(String operation) {
        server
                .stubFor(WireMock
                        .post(WireMock.urlPathEqualTo(OPERATIONS + operation))
                        .willReturn(WireMock.serverError()));
        return this;
    }

    public void verifyOperationRequestContaining(String operation, String expectedRequestJson) {
        server
                .verify(postRequestedFor(WireMock.urlPathEqualTo(OPERATIONS + operation))
                        .withRequestBody(WireMock.equalToJson(expectedRequestJson, true, true)));
    }

    public void verifyNoOperationRequest(String operation) {
        server.verify(0, postRequestedFor(WireMock.urlPathEqualTo(OPERATIONS + operation)));
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

    public CryptographyProviderV2ConnectorMock stubKeyRequestTypes(String responseJson) {
        server
                .stubFor(WireMock
                        .post(WireMock.urlPathEqualTo("/v2/cryptographyProvider/tokens/keyRequestTypes"))
                        .willReturn(WireMock.okJson(responseJson)));
        return this;
    }

    public CryptographyProviderV2ConnectorMock stubExportableKeyTypes(KeyRequestType type, KeyAlgorithm... algorithms)
            throws JsonProcessingException {
        ExportableKeyTypeV2Dto declaration = new ExportableKeyTypeV2Dto();
        declaration.setKeyRequestType(type);
        declaration.setAlgorithms(Set.of(algorithms));
        server
                .stubFor(WireMock
                        .post(WireMock.urlPathEqualTo(EXPORTABLE_KEY_TYPES))
                        .willReturn(
                                WireMock.okJson(ObjectMapperFactory.wire().writeValueAsString(List.of(declaration)))));
        return this;
    }

    public CryptographyProviderV2ConnectorMock stubNoExportableKeyTypes() {
        server.stubFor(WireMock.post(WireMock.urlPathEqualTo(EXPORTABLE_KEY_TYPES)).willReturn(WireMock.okJson("[]")));
        return this;
    }

    public CryptographyProviderV2ConnectorMock stubExportableKeyTypesUnreachable() {
        server
                .stubFor(WireMock
                        .post(WireMock.urlPathEqualTo(EXPORTABLE_KEY_TYPES))
                        .willReturn(WireMock.aResponse().withFault(Fault.CONNECTION_RESET_BY_PEER)));
        return this;
    }

    public CryptographyProviderV2ConnectorMock stubExportableKeyTypesFailing() {
        server.stubFor(WireMock.post(WireMock.urlPathEqualTo(EXPORTABLE_KEY_TYPES)).willReturn(WireMock.serverError()));
        return this;
    }

    public void verifyExportableKeyTypesRequestContaining(String expectedRequestJson) {
        verifyExportableKeyTypesRequestsContaining(1, expectedRequestJson);
    }

    public void verifyExportableKeyTypesRequestsContaining(int count, String expectedRequestJson) {
        server
                .verify(count, postRequestedFor(WireMock.urlPathEqualTo(EXPORTABLE_KEY_TYPES))
                        .withRequestBody(WireMock.equalToJson(expectedRequestJson, true, true)));
    }

    public void verifyExportableKeyTypesRequests(int count) {
        server.verify(count, postRequestedFor(WireMock.urlPathEqualTo(EXPORTABLE_KEY_TYPES)));
    }

    public void verifyScopedKeyRequestTypesRequestContaining(String expectedRequestJson) {
        server
                .verify(postRequestedFor(WireMock.urlPathEqualTo("/v2/cryptographyProvider/tokens/keyRequestTypes"))
                        .withRequestBody(WireMock.equalToJson(expectedRequestJson, true, true)));
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
