package com.otilm.core.util.mocks;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.github.tomakehurst.wiremock.client.ResponseDefinitionBuilder;
import com.github.tomakehurst.wiremock.extension.Parameters;
import com.github.tomakehurst.wiremock.extension.ResponseDefinitionTransformerV2;
import com.github.tomakehurst.wiremock.http.ResponseDefinition;
import com.github.tomakehurst.wiremock.stubbing.ServeEvent;
import java.security.PrivateKey;
import java.security.Signature;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

/**
 * WireMock extension answering every item of a sign request with a <em>real</em> signature under the item's identifier.
 * A stub names the signing key by {@link #KEY_REFERENCE}, and a v1 sign URL by its key-reference UUID.
 */
class RealSignerTransformer implements ResponseDefinitionTransformerV2 {

    static final String NAME = "real-signer";

    /** Stub parameter naming the registered signing key. */
    static final String KEY_REFERENCE = "keyReference";

    /** Stub parameter answering the items in reverse order. */
    static final String REVERSED_ORDER = "reversedOrder";

    /** Stub parameter answering every item without its identifier. */
    static final String WITHOUT_IDENTIFIERS = "withoutIdentifiers";

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
            Parameters parameters = serveEvent.getTransformerParameters();
            KeyEntry key = registeredKeyFor(serveEvent.getRequest().getUrl(), parameters);
            JsonNode items = OBJECT_MAPPER.readTree(serveEvent.getRequest().getBodyAsString()).path("data");
            List<ObjectNode> signatures = new ArrayList<>();
            for (JsonNode item : items) {
                signatures.add(signatureOf(key, item, parameters.getBoolean(WITHOUT_IDENTIFIERS, false)));
            }
            if (parameters.getBoolean(REVERSED_ORDER, false)) {
                Collections.reverse(signatures);
            }

            return ResponseDefinitionBuilder
                    .like(serveEvent.getResponseDefinition())
                    .withBody(signResponseJson(signatures))
                    .build();
        } catch (Exception e) {
            throw new IllegalStateException("Failed to compute signature in WireMock real-signer transformer", e);
        }
    }

    private KeyEntry registeredKeyFor(String url, Parameters parameters) {
        String keyReference = parameters.getString(KEY_REFERENCE, null);
        if (keyReference == null) {
            Matcher matcher = KEY_REF_UUID_PATTERN.matcher(url);
            if (!matcher.find()) {
                throw new IllegalStateException("No key reference UUID in sign URL: " + url);
            }
            keyReference = matcher.group(1);
        }
        KeyEntry entry = keysByReferenceUuid.get(keyReference);
        if (entry == null) {
            throw new IllegalStateException("No registered key for reference UUID: " + keyReference);
        }
        return entry;
    }

    private static ObjectNode signatureOf(KeyEntry key, JsonNode item, boolean withoutIdentifier) throws Exception {
        byte[] dtbs = Base64.getDecoder().decode(item.path("data").asText());
        ObjectNode signature = OBJECT_MAPPER.createObjectNode();
        signature.put("data", Base64.getEncoder().encodeToString(sign(key, dtbs)));
        JsonNode identifier = item.path("identifier");
        if (!withoutIdentifier && identifier.isTextual()) {
            signature.put("identifier", identifier.asText());
        }
        return signature;
    }

    private static byte[] sign(KeyEntry key, byte[] dtbs) throws Exception {
        Signature signature = Signature.getInstance(key.jcaSignatureAlgorithm(), BouncyCastleProvider.PROVIDER_NAME);
        signature.initSign(key.privateKey());
        signature.update(dtbs);
        return signature.sign();
    }

    /**
     * Matches the sign-response JSON shape of both connector contracts.
     */
    private static String signResponseJson(List<ObjectNode> signatures) {
        ObjectNode response = OBJECT_MAPPER.createObjectNode();
        ArrayNode signatureArray = response.putArray("signatures");
        signatureArray.addAll(signatures);
        return response.toString();
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
