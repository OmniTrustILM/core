package com.otilm.core.util.mocks;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.github.tomakehurst.wiremock.client.ResponseDefinitionBuilder;
import com.github.tomakehurst.wiremock.extension.ResponseDefinitionTransformerV2;
import com.github.tomakehurst.wiremock.http.ResponseDefinition;
import com.github.tomakehurst.wiremock.stubbing.ServeEvent;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import java.security.PrivateKey;
import java.security.Signature;
import java.util.Base64;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * WireMock extension backing {@link CryptographyProviderConnectorMock#stubRealSigning()}: routes each
 * sign request to the registered private key matching the key-reference UUID in the request URL and
 * signs the request's DTBS with it, producing a <em>real</em> signature.
 */
class RealSignerTransformer implements ResponseDefinitionTransformerV2 {

    static final String NAME = "real-signer";

    private static final ObjectMapper OBJECT_MAPPER = new ObjectMapper();
    private static final Pattern KEY_REF_UUID_PATTERN = Pattern.compile("/keys/([^/]+)/sign");

    private final Map<String, KeyEntry> keysByReferenceUuid = new ConcurrentHashMap<>();

    private record KeyEntry(PrivateKey privateKey, String jcaSignatureAlgorithm) {
    }

    void registerKey(UUID keyReferenceUuid, PrivateKey privateKey, String jcaSignatureAlgorithm) {
        keysByReferenceUuid.put(keyReferenceUuid.toString(), new KeyEntry(privateKey, jcaSignatureAlgorithm));
    }

    @Override
    public ResponseDefinition transform(ServeEvent serveEvent) {
        try {
            byte[] dtbs = extractDtbs(serveEvent);
            KeyEntry key = registeredKeyFor(serveEvent.getRequest().getUrl());
            byte[] signature = sign(key, dtbs);

            return ResponseDefinitionBuilder.like(serveEvent.getResponseDefinition())
                    .withBody(signResponseJson(signature))
                    .build();
        } catch (Exception e) {
            throw new IllegalStateException("Failed to compute signature in WireMock real-signer transformer", e);
        }
    }

    private static byte[] extractDtbs(ServeEvent serveEvent) throws Exception {
        JsonNode body = OBJECT_MAPPER.readTree(serveEvent.getRequest().getBodyAsString());
        return Base64.getDecoder().decode(body.at("/data/0/data").asText());
    }

    private KeyEntry registeredKeyFor(String url) {
        Matcher matcher = KEY_REF_UUID_PATTERN.matcher(url);
        if (!matcher.find()) {
            throw new IllegalStateException("No key reference UUID in sign URL: " + url);
        }
        KeyEntry entry = keysByReferenceUuid.get(matcher.group(1));
        if (entry == null) {
            throw new IllegalStateException("No registered key for reference UUID: " + matcher.group(1));
        }
        return entry;
    }

    private static byte[] sign(KeyEntry key, byte[] dtbs) throws Exception {
        Signature signature = Signature.getInstance(key.jcaSignatureAlgorithm(), BouncyCastleProvider.PROVIDER_NAME);
        signature.initSign(key.privateKey());
        signature.update(dtbs);
        return signature.sign();
    }

    /**
     * Matches the connector-side {@code SignDataResponseDto} JSON shape.
     */
    private static String signResponseJson(byte[] signature) {
        return "{\"signatures\":[{\"data\":\"" + Base64.getEncoder().encodeToString(signature) + "\"}]}";
    }

    @Override
    public String getName() {
        return NAME;
    }

    @Override
    public boolean applyGlobally() {
        return false;
    }
}
