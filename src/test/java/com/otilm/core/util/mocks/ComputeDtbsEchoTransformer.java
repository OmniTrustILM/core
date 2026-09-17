package com.otilm.core.util.mocks;

import com.fasterxml.jackson.databind.JsonNode;
import com.github.tomakehurst.wiremock.client.ResponseDefinitionBuilder;
import com.github.tomakehurst.wiremock.extension.ResponseDefinitionTransformerV2;
import com.github.tomakehurst.wiremock.http.ResponseDefinition;
import com.github.tomakehurst.wiremock.stubbing.ServeEvent;
import com.otilm.api.model.common.enums.cryptography.DigestAlgorithm;
import com.otilm.api.model.common.enums.cryptography.SignatureAlgorithm;
import com.otilm.api.model.connector.signatures.contentsigning.common.ComputeDtbsResponseDto;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.Base64;

/**
 * WireMock extension backing {@link ContentSigningFormattingMock#stubBaselineAndTimestampOperations()}.
 */
class ComputeDtbsEchoTransformer implements ResponseDefinitionTransformerV2 {

    static final String NAME = "content-signing-dtbs-echo";

    static final String FOREIGN_NAME = "content-signing-dtbs-foreign-echo";

    private static final byte[] FIXED_DTBS = "data-to-be-signed".getBytes(StandardCharsets.UTF_8);

    private static final byte[] FIXED_FORMATTING_CONTEXT = "formatting-context".getBytes(StandardCharsets.UTF_8);

    private final String name;
    private final byte[] foreignContent;

    ComputeDtbsEchoTransformer() {
        this.name = NAME;
        this.foreignContent = null;
    }

    ComputeDtbsEchoTransformer(byte[] foreignContent) {
        this.name = FOREIGN_NAME;
        this.foreignContent = foreignContent.clone();
    }

    @Override
    public ResponseDefinition transform(ServeEvent serveEvent) {
        try {
            JsonNode body = BaseConnectorMock.OBJECT_MAPPER.readTree(serveEvent.getRequest().getBodyAsString());
            DigestAlgorithm committed = committedDigest(body);

            ComputeDtbsResponseDto response = new ComputeDtbsResponseDto();
            response.setDtbs(FIXED_DTBS);
            response.setFormattingContext(FIXED_FORMATTING_CONTEXT);
            response.setDocumentDigestAlgorithm(committed);
            response.setDocumentDigest(digest(committed, committedContent(body)));

            return ResponseDefinitionBuilder
                    .like(serveEvent.getResponseDefinition())
                    .withBody(BaseConnectorMock.OBJECT_MAPPER.writeValueAsString(response))
                    .build();
        } catch (Exception e) {
            throw new IllegalStateException("Failed to build computeDtbs response in WireMock echo transformer", e);
        }
    }

    private static DigestAlgorithm committedDigest(JsonNode body) {
        JsonNode named = body.at("/signatureAlgorithm");
        if (!named.isTextual()) {
            return DigestAlgorithm.SHA_256; // default fallback
        }
        SignatureAlgorithm signatureAlgorithm = SignatureAlgorithm.findByCode(named.asText());
        return DigestAlgorithm.findByOid(signatureAlgorithm.getDigestAlgorithmIdentifier().getAlgorithm().getId());
    }

    private byte[] committedContent(JsonNode body) {
        if (foreignContent != null) {
            return foreignContent;
        }
        return Base64.getDecoder().decode(body.at("/document/document").asText());
    }

    private static byte[] digest(DigestAlgorithm algorithm, byte[] content) throws Exception {
        return MessageDigest.getInstance(algorithm.getCode()).digest(content);
    }

    @Override
    public String getName() {
        return name;
    }

    @Override
    public boolean applyGlobally() {
        return false;
    }
}
