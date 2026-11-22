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
import com.otilm.api.model.common.enums.cryptography.DigestAlgorithm;
import com.otilm.api.model.common.enums.cryptography.SignatureAlgorithm;
import com.otilm.api.model.common.enums.cryptography.SignatureInputMode;
import java.security.PrivateKey;
import java.security.Signature;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.MGF1ParameterSpec;
import java.security.spec.PSSParameterSpec;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import org.bouncycastle.asn1.ASN1Encoding;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.DERNull;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.DigestInfo;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

/**
 * WireMock extension answering every item of a sign request with a <em>real</em> signature under the item's identifier.
 * A stub names the signing key by {@link #KEY_REFERENCE}, and a v1 sign URL by its key-reference UUID. A v2 request
 * whose {@code signatureInputMode} is {@code dataDigest} has each item signed as the digest it is, as a provider
 * implementing that mode does, so Core's check of each signature against its digest passes.
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
    private static final String DATA_DIGEST = SignatureInputMode.DATA_DIGEST.getCode();

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
            JsonNode body = OBJECT_MAPPER.readTree(serveEvent.getRequest().getBodyAsString());
            boolean dataDigest = DATA_DIGEST.equals(body.path("signatureInputMode").asText());
            List<ObjectNode> signatures = new ArrayList<>();
            for (JsonNode item : body.path("data")) {
                signatures.add(signatureOf(key, item, dataDigest, parameters.getBoolean(WITHOUT_IDENTIFIERS, false)));
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

    private static ObjectNode signatureOf(KeyEntry key, JsonNode item, boolean dataDigest, boolean withoutIdentifier)
            throws Exception {
        byte[] itemBytes = Base64.getDecoder().decode(item.path("data").asText());
        byte[] signatureValue = dataDigest ? signDigest(key, itemBytes) : sign(key, itemBytes);
        ObjectNode signature = OBJECT_MAPPER.createObjectNode();
        signature.put("data", Base64.getEncoder().encodeToString(signatureValue));
        JsonNode identifier = item.path("identifier");
        if (!withoutIdentifier && identifier.isTextual()) {
            signature.put("identifier", identifier.asText());
        }
        return signature;
    }

    private static byte[] sign(KeyEntry key, byte[] dtbs) throws Exception {
        return signRaw(key.privateKey(), key.jcaSignatureAlgorithm(), null, dtbs);
    }

    /**
     * Signs the bytes as the digest the key's algorithm fixes, without hashing them again: PKCS#1 v1.5 over a
     * DigestInfo with NULL parameters, PSS with the digest's own MGF1 and salt length, and ECDSA over the digest.
     */
    private static byte[] signDigest(KeyEntry key, byte[] digest) throws Exception {
        SignatureAlgorithm algorithm = SignatureAlgorithm.findByCode(key.jcaSignatureAlgorithm());
        ASN1ObjectIdentifier digestOid = algorithm.getDigestAlgorithmIdentifier().getAlgorithm();
        return switch (algorithm) {
            case SHA256_WITH_RSA, SHA384_WITH_RSA, SHA512_WITH_RSA ->
                signRaw(key.privateKey(), "NONEwithRSA", null, digestInfo(digestOid, digest));
            case SHA256_WITH_RSA_PSS, SHA384_WITH_RSA_PSS, SHA512_WITH_RSA_PSS ->
                signRaw(key.privateKey(), "RAWRSASSA-PSS", pssParameters(digestOid), digest);
            case SHA256_WITH_ECDSA, SHA384_WITH_ECDSA, SHA512_WITH_ECDSA ->
                signRaw(key.privateKey(), "NONEwithECDSA", null, digest);
            default -> throw new IllegalStateException(algorithm.getCode() + " cannot sign a data digest");
        };
    }

    private static byte[] signRaw(PrivateKey privateKey, String jcaAlgorithm, AlgorithmParameterSpec parameters,
            byte[] input) throws Exception {
        Signature signature = Signature.getInstance(jcaAlgorithm, BouncyCastleProvider.PROVIDER_NAME);
        if (parameters != null) {
            signature.setParameter(parameters);
        }
        signature.initSign(privateKey);
        signature.update(input);
        return signature.sign();
    }

    private static byte[] digestInfo(ASN1ObjectIdentifier digestOid, byte[] digest) throws Exception {
        return new DigestInfo(new AlgorithmIdentifier(digestOid, DERNull.INSTANCE), digest)
                .getEncoded(ASN1Encoding.DER);
    }

    private static PSSParameterSpec pssParameters(ASN1ObjectIdentifier digestOid) {
        DigestAlgorithm digest = DigestAlgorithm.findByOid(digestOid.getId());
        return new PSSParameterSpec(digest.getCode(), "MGF1", new MGF1ParameterSpec(digest.getCode()),
                digest.getDigestSizeBytes(), PSSParameterSpec.TRAILER_FIELD_BC);
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
