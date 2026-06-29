package com.otilm.core.util.mocks;

import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.github.tomakehurst.wiremock.client.ResponseDefinitionBuilder;
import com.github.tomakehurst.wiremock.extension.ResponseDefinitionTransformerV2;
import com.github.tomakehurst.wiremock.http.ResponseDefinition;
import com.github.tomakehurst.wiremock.stubbing.ServeEvent;

/**
 * Base for the WireMock extensions implementing the two phases of the RFC 3161 formatting contract
 * ({@link TimestampingFormatDtbsTransformer}, {@link TimestampingFormatResponseTransformer}).
 *
 * <p>Both phases rebuild the TSTInfo deterministically from their request DTO's fields — the client
 * sends the same serial number, signing time, policy, nonce and message imprint in both round trips —
 * so the messageDigest signed in phase 1 matches the TSTInfo embedded in phase 2 without any
 * cross-request state in the mock.
 */
abstract class TimestampingFormattingTransformer implements ResponseDefinitionTransformerV2 {

    /**
     * The DTOs use Java time types ({@code Instant}, {@code Duration}); registering all discoverable
     * modules picks up jackson-datatype-jsr310 the same way the production WebClient codecs do.
     */
    private static final ObjectMapper DTO_MAPPER = new ObjectMapper()
            .findAndRegisterModules()
            .disable(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES);

    protected static <T> T readRequest(ServeEvent serveEvent, Class<T> requestType) throws Exception {
        return DTO_MAPPER.readValue(serveEvent.getRequest().getBodyAsString(), requestType);
    }

    protected static ResponseDefinition jsonResponse(ServeEvent serveEvent, Object responseDto) throws Exception {
        return ResponseDefinitionBuilder.like(serveEvent.getResponseDefinition())
                .withBody(DTO_MAPPER.writeValueAsString(responseDto))
                .build();
    }

    @Override
    public final boolean applyGlobally() {
        return false;
    }
}
