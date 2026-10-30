package com.otilm.core.util.mocks;

import com.github.tomakehurst.wiremock.client.WireMock;
import com.otilm.api.model.client.connector.InfoResponse;
import com.otilm.api.model.common.enums.cryptography.KeyAlgorithm;
import com.otilm.api.model.common.enums.cryptography.SignatureAlgorithm;
import com.otilm.api.model.core.connector.EndpointDto;
import com.otilm.api.model.core.connector.FunctionGroupCode;
import com.otilm.core.util.seeders.FunctionGroupSeeder;
import java.security.PrivateKey;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.UUID;

/**
 * Mock of a V1 cryptography-provider connector.
 */
public class CryptographyProviderConnectorMock extends BaseConnectorMock {

    private final RealSignerTransformer realSignerTransformer;

    CryptographyProviderConnectorMock(FunctionGroupSeeder functionGroupSeeder) {
        this(functionGroupSeeder, new RealSignerTransformer());
    }

    private CryptographyProviderConnectorMock(FunctionGroupSeeder functionGroupSeeder,
            RealSignerTransformer realSignerTransformer) {
        super(realSignerTransformer);
        this.realSignerTransformer = realSignerTransformer;
        List<EndpointDto> endpoints = cryptographyProviderEndpoints();
        functionGroupSeeder.seed(FunctionGroupCode.CRYPTOGRAPHY_PROVIDER, endpoints);
        InfoResponse function = new InfoResponse(List.of("SOFT"), FunctionGroupCode.CRYPTOGRAPHY_PROVIDER, endpoints);
        stubV1FunctionGroups(List.of(function));
    }

    private static List<EndpointDto> cryptographyProviderEndpoints() {
        String[][] specs = {
                {"POST", "/v1/cryptographyProvider/tokens", "createTokenInstance"},
                {"GET", "/v1/cryptographyProvider/tokens", "listTokenInstances"},
                {"GET", "/v1/cryptographyProvider/tokens/{uuid}", "getTokenInstance"},
                {"POST", "/v1/cryptographyProvider/tokens/{uuid}", "updateTokenInstance"},
                {"DELETE", "/v1/cryptographyProvider/tokens/{uuid}", "removeTokenInstance"},
                {"GET", "/v1/cryptographyProvider/tokens/{uuid}/status", "getTokenInstanceStatus"},
                {"PATCH", "/v1/cryptographyProvider/tokens/{uuid}/activate", "activateTokenInstance"},
                {"PATCH", "/v1/cryptographyProvider/tokens/{uuid}/deactivate", "deactivateTokenInstance"},
                {
                        "GET",
                        "/v1/cryptographyProvider/tokens/{uuid}/activate/attributes",
                        "listTokenInstanceActivationAttributes"},
                {
                        "POST",
                        "/v1/cryptographyProvider/tokens/{uuid}/activate/attributes/validate",
                        "validateTokenInstanceActivationAttributes"},
                {"GET", "/v1/cryptographyProvider/tokens/{uuid}/tokenProfile/attributes", "listTokenProfileAttributes"},
                {
                        "POST",
                        "/v1/cryptographyProvider/tokens/{uuid}/tokenProfile/attributes/validate",
                        "validateTokenProfileAttributes"},
                {"GET", "/v1/cryptographyProvider/tokens/{uuid}/keys", "listKeys"},
                {"GET", "/v1/cryptographyProvider/tokens/{uuid}/keys/{keyUuid}", "getKey"},
                {"DELETE", "/v1/cryptographyProvider/tokens/{uuid}/keys/{keyUuid}", "destroyKey"},
                {"POST", "/v1/cryptographyProvider/tokens/{uuid}/keys/pair", "createKeyPair"},
                {"GET", "/v1/cryptographyProvider/tokens/{uuid}/keys/pair/attributes", "listCreateKeyPairAttributes"},
                {
                        "POST",
                        "/v1/cryptographyProvider/tokens/{uuid}/keys/pair/attributes/validate",
                        "validateCreateKeyPairAttributes"},
                {"POST", "/v1/cryptographyProvider/tokens/{uuid}/keys/secret", "createSecretKey"},
                {
                        "GET",
                        "/v1/cryptographyProvider/tokens/{uuid}/keys/secret/attributes",
                        "listCreateSecretKeyAttributes"},
                {
                        "POST",
                        "/v1/cryptographyProvider/tokens/{uuid}/keys/secret/attributes/validate",
                        "validateCreateSecretKeyAttributes"},
                {"POST", "/v1/cryptographyProvider/tokens/{uuid}/keys/random", "randomData"},
                {"GET", "/v1/cryptographyProvider/tokens/{uuid}/keys/random/attributes", "listRandomAttributes"},
                {
                        "POST",
                        "/v1/cryptographyProvider/tokens/{uuid}/keys/random/attributes/validate",
                        "validateRandomAttributes"},
                {"POST", "/v1/cryptographyProvider/tokens/{uuid}/keys/{keyUuid}/encrypt", "encryptData"},
                {"POST", "/v1/cryptographyProvider/tokens/{uuid}/keys/{keyUuid}/decrypt", "decryptData"},
                {"POST", "/v1/cryptographyProvider/tokens/{uuid}/keys/{keyUuid}/sign", "signData"},
                {"POST", "/v1/cryptographyProvider/tokens/{uuid}/keys/{keyUuid}/verify", "verifyData"},
                {"GET", "/v1/cryptographyProvider/{kind}/attributes", "listAttributeDefinitions"},
                {"POST", "/v1/cryptographyProvider/{kind}/attributes/validate", "validateAttributes"},
                {"GET", "/v1/cryptographyProvider/callbacks/token/{option}/attributes", "getCreateTokenAttributes"},};

        List<EndpointDto> endpoints = new ArrayList<>();
        for (String[] spec : specs) {
            EndpointDto endpoint = new EndpointDto();
            endpoint.setUuid(UUID.randomUUID().toString());
            endpoint.setMethod(spec[0]);
            endpoint.setContext(spec[1]);
            endpoint.setName(spec[2]);
            endpoint.setRequired(true);
            endpoints.add(endpoint);
        }
        return endpoints;
    }

    public CryptographyProviderConnectorMock stubTokenInstanceCreation(UUID tokenUuid) {
        server
                .stubFor(WireMock
                        .get(WireMock.urlPathMatching("/v1/cryptographyProvider/[^/]+/attributes"))
                        .willReturn(WireMock.okJson("[]")));
        server
                .stubFor(WireMock
                        .post(WireMock.urlPathMatching("/v1/cryptographyProvider/[^/]+/attributes/validate"))
                        .willReturn(WireMock.okJson("true")));
        server
                .stubFor(WireMock
                        .post(WireMock.urlPathEqualTo("/v1/cryptographyProvider/tokens"))
                        .willReturn(WireMock.okJson("{\"uuid\":\"" + tokenUuid + "\",\"name\":\"soft-token\"}")));
        server
                .stubFor(WireMock
                        .get(WireMock.urlPathMatching("/v1/cryptographyProvider/tokens/[^/]+/status"))
                        .willReturn(WireMock.okJson("{\"status\":\"Activated\"}")));
        return this;
    }

    public CryptographyProviderConnectorMock stubTokenProfileCreation() {
        server
                .stubFor(WireMock
                        .get(WireMock.urlPathMatching("/v1/cryptographyProvider/tokens/[^/]+/tokenProfile/attributes"))
                        .willReturn(WireMock.okJson("[]")));
        server
                .stubFor(WireMock
                        .post(WireMock
                                .urlPathMatching(
                                        "/v1/cryptographyProvider/tokens/[^/]+/tokenProfile/attributes/validate"))
                        .willReturn(WireMock.okJson("true")));
        return this;
    }

    public CryptographyProviderConnectorMock stubKeyPairCreation(String base64Spki) {
        return stubKeyPairCreation(base64Spki, KeyAlgorithm.RSA, UUID.randomUUID());
    }

    public CryptographyProviderConnectorMock stubKeyPairCreation(String base64Spki, KeyAlgorithm algorithm,
            UUID privateKeyUuid) {
        server
                .stubFor(WireMock
                        .get(WireMock.urlPathMatching("/v1/cryptographyProvider/tokens/[^/]+/keys/pair/attributes"))
                        .willReturn(WireMock.okJson("[]")));
        server
                .stubFor(WireMock
                        .post(WireMock
                                .urlPathMatching("/v1/cryptographyProvider/tokens/[^/]+/keys/pair/attributes/validate"))
                        .willReturn(WireMock.okJson("true")));
        server
                .stubFor(WireMock
                        .post(WireMock.urlPathMatching("/v1/cryptographyProvider/tokens/[^/]+/keys/pair"))
                        .willReturn(WireMock
                                .okJson("{" + "\"privateKeyData\":{\"name\":\"privateKey\",\"uuid\":\"" + privateKeyUuid
                                        + "\"," + "\"keyData\":{\"type\":\"Private\",\"algorithm\":\""
                                        + algorithm.getCode()
                                        + "\",\"format\":\"Custom\",\"value\":{\"securityCategory\":\"5\"}}},"
                                        + "\"publicKeyData\":{\"name\":\"publicKey\",\"uuid\":\"" + UUID.randomUUID()
                                        + "\"," + "\"keyData\":{\"type\":\"Public\",\"algorithm\":\""
                                        + algorithm.getCode() + "\",\"format\":\"SubjectPublicKeyInfo\",\"value\":\""
                                        + base64Spki + "\"}}}")));
        return this;
    }

    public CryptographyProviderConnectorMock stubRealSigning() {
        server
                .stubFor(WireMock
                        .post(WireMock.urlPathMatching("/v1/cryptographyProvider/tokens/[^/]+/keys/[^/]+/sign"))
                        .willReturn(WireMock
                                .aResponse()
                                .withStatus(200)
                                .withHeader("Content-Type", "application/json")
                                .withTransformers(RealSignerTransformer.NAME)));
        return this;
    }

    public CryptographyProviderConnectorMock registerSigningKey(UUID keyReferenceUuid, PrivateKey privateKey,
            SignatureAlgorithm signatureAlgorithm) {
        realSignerTransformer.registerKey(keyReferenceUuid, privateKey, signatureAlgorithm.getCode());
        return this;
    }

    public CryptographyProviderConnectorMock stubSignData(byte[] signature) {
        String sig = Base64.getEncoder().encodeToString(signature);
        server
                .stubFor(WireMock
                        .post(WireMock.urlPathMatching("/v1/cryptographyProvider/tokens/[^/]+/keys/[^/]+/sign"))
                        .willReturn(WireMock.okJson("{\"signatures\":[{\"data\":\"" + sig + "\"}]}")));
        return this;
    }

    public CryptographyProviderConnectorMock verifyNoDataWasSigned() {
        server
                .verify(0, WireMock
                        .postRequestedFor(
                                WireMock.urlPathMatching("/v1/cryptographyProvider/tokens/[^/]+/keys/[^/]+/sign")));
        return this;
    }
}
