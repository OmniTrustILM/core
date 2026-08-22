package com.otilm.core.util.mocks;

import com.fasterxml.jackson.databind.JsonNode;
import com.github.tomakehurst.wiremock.client.ResponseDefinitionBuilder;
import com.github.tomakehurst.wiremock.extension.ResponseDefinitionTransformerV2;
import com.github.tomakehurst.wiremock.http.ResponseDefinition;
import com.github.tomakehurst.wiremock.stubbing.ServeEvent;
import com.otilm.api.model.common.enums.cryptography.DigestAlgorithm;
import com.otilm.api.model.connector.signatures.contentsigning.common.ComputeDtbsResponseDto;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.Base64;

/**
 * WireMock extension backing {@link ContentSigningFormattingMock#stubBaselineAndTimestampOperations()}: answers
 * {@code computeDtbs} with the SHA-256 of the document the request carried, which is the echo the platform's binding
 * check compares against the authorized digest.
 *
 * <p>
 * Constructed with fixed content instead, it echoes the digest of that content and ignores the request — a connector
 * that committed to a different document than the one it was handed. Both variants are registered under distinct names,
 * because a WireMock extension can only be registered at server creation.
 * </p>
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
            ComputeDtbsResponseDto response = new ComputeDtbsResponseDto();
            response.setDtbs(FIXED_DTBS);
            response.setFormattingContext(FIXED_FORMATTING_CONTEXT);
            response.setDocumentDigestAlgorithm(DigestAlgorithm.SHA_256);
            response.setDocumentDigest(sha256(committedContent(serveEvent)));

            return ResponseDefinitionBuilder
                    .like(serveEvent.getResponseDefinition())
                    .withBody(BaseConnectorMock.OBJECT_MAPPER.writeValueAsString(response))
                    .build();
        } catch (Exception e) {
            throw new IllegalStateException("Failed to build computeDtbs response in WireMock echo transformer", e);
        }
    }

    private byte[] committedContent(ServeEvent serveEvent) throws Exception {
        if (foreignContent != null) {
            return foreignContent;
        }
        JsonNode body = BaseConnectorMock.OBJECT_MAPPER.readTree(serveEvent.getRequest().getBodyAsString());
        return Base64.getDecoder().decode(body.at("/document/document").asText());
    }

    private static byte[] sha256(byte[] content) throws Exception {
        return MessageDigest.getInstance("SHA-256").digest(content);
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
