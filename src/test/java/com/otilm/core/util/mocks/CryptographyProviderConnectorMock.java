package com.otilm.core.util.mocks;

import com.otilm.api.model.client.connector.InfoResponse;
import com.otilm.api.model.core.connector.EndpointDto;
import com.otilm.api.model.core.connector.FunctionGroupCode;
import com.otilm.core.util.seeders.FunctionGroupSeeder;
import com.github.tomakehurst.wiremock.client.WireMock;

import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.UUID;

/**
 * Mock of a V1 cryptography-provider connector — stubs {@code GET /v1} to report the
 * {@code CRYPTOGRAPHY_PROVIDER} function group (kind {@code SOFT}) advertising every required endpoint.
 * Starting the mock also seeds the function group and its required endpoints into the test database
 * from the same endpoint list, so {@code ConnectorV1Adapter#validateFunctionGroups} performs the real
 * production check at registration: DB-required endpoints vs. what this mock advertises.
 */
public class CryptographyProviderConnectorMock extends BaseConnectorMock {

    CryptographyProviderConnectorMock(FunctionGroupSeeder functionGroupSeeder) {
        List<EndpointDto> endpoints = cryptographyProviderEndpoints();
        functionGroupSeeder.seed(FunctionGroupCode.CRYPTOGRAPHY_PROVIDER, endpoints);
        InfoResponse function = new InfoResponse(
                List.of("SOFT"),
                FunctionGroupCode.CRYPTOGRAPHY_PROVIDER,
                endpoints);
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
                {"GET", "/v1/cryptographyProvider/tokens/{uuid}/activate/attributes", "listTokenInstanceActivationAttributes"},
                {"POST", "/v1/cryptographyProvider/tokens/{uuid}/activate/attributes/validate", "validateTokenInstanceActivationAttributes"},
                {"GET", "/v1/cryptographyProvider/tokens/{uuid}/tokenProfile/attributes", "listTokenProfileAttributes"},
                {"POST", "/v1/cryptographyProvider/tokens/{uuid}/tokenProfile/attributes/validate", "validateTokenProfileAttributes"},
                {"GET", "/v1/cryptographyProvider/tokens/{uuid}/keys", "listKeys"},
                {"GET", "/v1/cryptographyProvider/tokens/{uuid}/keys/{keyUuid}", "getKey"},
                {"DELETE", "/v1/cryptographyProvider/tokens/{uuid}/keys/{keyUuid}", "destroyKey"},
                {"POST", "/v1/cryptographyProvider/tokens/{uuid}/keys/pair", "createKeyPair"},
                {"GET", "/v1/cryptographyProvider/tokens/{uuid}/keys/pair/attributes", "listCreateKeyPairAttributes"},
                {"POST", "/v1/cryptographyProvider/tokens/{uuid}/keys/pair/attributes/validate", "validateCreateKeyPairAttributes"},
                {"POST", "/v1/cryptographyProvider/tokens/{uuid}/keys/secret", "createSecretKey"},
                {"GET", "/v1/cryptographyProvider/tokens/{uuid}/keys/secret/attributes", "listCreateSecretKeyAttributes"},
                {"POST", "/v1/cryptographyProvider/tokens/{uuid}/keys/secret/attributes/validate", "validateCreateSecretKeyAttributes"},
                {"POST", "/v1/cryptographyProvider/tokens/{uuid}/keys/random", "randomData"},
                {"GET", "/v1/cryptographyProvider/tokens/{uuid}/keys/random/attributes", "listRandomAttributes"},
                {"POST", "/v1/cryptographyProvider/tokens/{uuid}/keys/random/attributes/validate", "validateRandomAttributes"},
                {"POST", "/v1/cryptographyProvider/tokens/{uuid}/keys/{keyUuid}/encrypt", "encryptData"},
                {"POST", "/v1/cryptographyProvider/tokens/{uuid}/keys/{keyUuid}/decrypt", "decryptData"},
                {"POST", "/v1/cryptographyProvider/tokens/{uuid}/keys/{keyUuid}/sign", "signData"},
                {"POST", "/v1/cryptographyProvider/tokens/{uuid}/keys/{keyUuid}/verify", "verifyData"},
                {"GET", "/v1/cryptographyProvider/{kind}/attributes", "listAttributeDefinitions"},
                {"POST", "/v1/cryptographyProvider/{kind}/attributes/validate", "validateAttributes"},
                {"GET", "/v1/cryptographyProvider/callbacks/token/{option}/attributes", "getCreateTokenAttributes"},
        };

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

    /**
     * Stubs the runtime endpoints hit by {@code TokenInstanceExternalService#createTokenInstance}: kind attribute
     * listing/validation, token creation, and status. {@code tokenUuid} is the UUID the connector reports
     * for the created token instance — Core persists it and uses it on every subsequent token call.
     */
    public CryptographyProviderConnectorMock stubTokenInstanceCreation(UUID tokenUuid) {
        server.stubFor(WireMock.get(WireMock.urlPathMatching("/v1/cryptographyProvider/[^/]+/attributes"))
                .willReturn(WireMock.okJson("[]")));
        server.stubFor(WireMock.post(WireMock.urlPathMatching("/v1/cryptographyProvider/[^/]+/attributes/validate"))
                .willReturn(WireMock.okJson("true")));
        server.stubFor(WireMock.post(WireMock.urlPathEqualTo("/v1/cryptographyProvider/tokens"))
                .willReturn(WireMock.okJson("{\"uuid\":\"" + tokenUuid + "\",\"name\":\"soft-token\"}")));
        server.stubFor(WireMock.get(WireMock.urlPathMatching("/v1/cryptographyProvider/tokens/[^/]+/status"))
                .willReturn(WireMock.okJson("{\"status\":\"Activated\"}")));
        return this;
    }

    /**
     * Stubs the token-profile attribute listing/validation endpoints hit by
     * {@code TokenProfileExternalService#createTokenProfile}.
     */
    public CryptographyProviderConnectorMock stubTokenProfileCreation() {
        server.stubFor(WireMock.get(WireMock.urlPathMatching("/v1/cryptographyProvider/tokens/[^/]+/tokenProfile/attributes"))
                .willReturn(WireMock.okJson("[]")));
        server.stubFor(WireMock.post(WireMock.urlPathMatching("/v1/cryptographyProvider/tokens/[^/]+/tokenProfile/attributes/validate"))
                .willReturn(WireMock.okJson("true")));
        return this;
    }

    /**
     * Stubs the create-key-pair endpoints hit by {@code CryptographicKeyService#createKey}. The public key
     * is reported in {@code SubjectPublicKeyInfo} format with the given Base64-encoded SPKI, so Core derives
     * the same fingerprint a certificate built from the matching public key will carry — letting the two be
     * associated later.
     */
    public CryptographyProviderConnectorMock stubKeyPairCreation(String base64Spki) {
        server.stubFor(WireMock.get(WireMock.urlPathMatching("/v1/cryptographyProvider/tokens/[^/]+/keys/pair/attributes"))
                .willReturn(WireMock.okJson("[]")));
        server.stubFor(WireMock.post(WireMock.urlPathMatching("/v1/cryptographyProvider/tokens/[^/]+/keys/pair/attributes/validate"))
                .willReturn(WireMock.okJson("true")));
        server.stubFor(WireMock.post(WireMock.urlPathMatching("/v1/cryptographyProvider/tokens/[^/]+/keys/pair"))
                .willReturn(WireMock.okJson("{"
                        + "\"privateKeyData\":{\"name\":\"privateKey\",\"uuid\":\"" + UUID.randomUUID() + "\","
                        + "\"keyData\":{\"type\":\"Private\",\"algorithm\":\"RSA\",\"format\":\"Custom\",\"value\":{\"securityCategory\":\"5\"}}},"
                        + "\"publicKeyData\":{\"name\":\"publicKey\",\"uuid\":\"" + UUID.randomUUID() + "\","
                        + "\"keyData\":{\"type\":\"Public\",\"algorithm\":\"RSA\",\"format\":\"SubjectPublicKeyInfo\",\"value\":\"" + base64Spki + "\"}}}")));
        return this;
    }

    /**
     * Stubs the data-signing endpoint hit by {@code CryptographicOperationService#signDataWithoutEventHistory},
     * returning the given signature bytes (base64-encoded) under {@code signatures[0].data}. The bytes need not
     * be a valid signature — downstream consumers in tests treat them as opaque.
     */
    public CryptographyProviderConnectorMock stubSignData(byte[] signature) {
        String sig = Base64.getEncoder().encodeToString(signature);
        server.stubFor(WireMock.post(WireMock.urlPathMatching("/v1/cryptographyProvider/tokens/[^/]+/keys/[^/]+/sign"))
                .willReturn(WireMock.okJson("{\"signatures\":[{\"data\":\"" + sig + "\"}]}")));
        return this;
    }
}
