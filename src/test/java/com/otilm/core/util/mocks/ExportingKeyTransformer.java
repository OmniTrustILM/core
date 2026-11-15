package com.otilm.core.util.mocks;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.github.tomakehurst.wiremock.client.ResponseDefinitionBuilder;
import com.github.tomakehurst.wiremock.extension.ResponseDefinitionTransformerV2;
import com.github.tomakehurst.wiremock.http.ResponseDefinition;
import com.github.tomakehurst.wiremock.stubbing.ServeEvent;
import com.otilm.api.model.common.enums.cryptography.KeyAlgorithm;
import com.otilm.core.util.ExportEnvelopeFixtures;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.concurrent.atomic.AtomicReference;

/**
 * WireMock extension answering a v2 key export as a connector does: the registered private key protected under the very
 * passphrase the request carries, in the contract's pinned envelope, and the key it describes. The described key can
 * differ from the protected one, as for a connector that exports the wrong key.
 */
class ExportingKeyTransformer implements ResponseDefinitionTransformerV2 {

    static final String NAME = "exporting-key";

    private static final ObjectMapper OBJECT_MAPPER = new ObjectMapper();

    private final AtomicReference<ExportedKey> exported = new AtomicReference<>();

    /**
     * @param protectedKey the private key the envelope protects
     * @param algorithm the algorithm of the described key
     * @param length the length of the described key
     * @param describedKey the public key the answer describes
     */
    record ExportedKey(PrivateKey protectedKey, KeyAlgorithm algorithm, int length, PublicKey describedKey) {
    }

    void register(ExportedKey key) {
        exported.set(key);
    }

    @Override
    public ResponseDefinition transform(ServeEvent serveEvent) {
        try {
            ExportedKey key = exported.get();
            char[] passphrase = OBJECT_MAPPER
                    .readTree(serveEvent.getRequest().getBodyAsString())
                    .path("passphrase")
                    .asText()
                    .toCharArray();
            byte[] envelope = ExportEnvelopeFixtures.pinnedEnvelope(key.protectedKey(), passphrase);
            return ResponseDefinitionBuilder
                    .like(serveEvent.getResponseDefinition())
                    .withBody(ExportEnvelopeFixtures
                            .keyPairResponseJson(envelope, key.algorithm(), key.length(), key.describedKey()))
                    .build();
        } catch (Exception e) {
            throw new IllegalStateException("Failed to export the key in the WireMock exporting-key transformer", e);
        }
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
