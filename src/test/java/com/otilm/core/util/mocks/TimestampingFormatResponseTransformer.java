package com.otilm.core.util.mocks;

import com.otilm.api.model.connector.signatures.formatting.FormattedResponseDto;
import com.otilm.api.model.connector.signatures.formatting.TimestampingFormatResponseRequestDto;
import com.otilm.core.signing.tsa.TimestampTokenTestUtil;
import com.github.tomakehurst.wiremock.http.ResponseDefinition;
import com.github.tomakehurst.wiremock.stubbing.ServeEvent;

/**
 * Phase 2 of the RFC 3161 formatting contract ({@code formatResponse}), backing
 * {@link TimestampingFormattingConnectorMock#stubFormatResponse()}: assembles a real
 * {@code TimeStampToken} embedding the externally produced signature carried by the request.
 */
class TimestampingFormatResponseTransformer extends TimestampingFormattingTransformer {

    static final String NAME = "tsp-format-response";

    @Override
    public ResponseDefinition transform(ServeEvent serveEvent) {
        try {
            TimestampingFormatResponseRequestDto request = readRequest(serveEvent, TimestampingFormatResponseRequestDto.class);

            FormattedResponseDto response = new FormattedResponseDto();
            response.setResponse(timestampTokenFor(request));
            return jsonResponse(serveEvent, response);
        } catch (Exception e) {
            throw new IllegalStateException("Failed to assemble timestamp token in WireMock formatting transformer", e);
        }
    }

    private static byte[] timestampTokenFor(TimestampingFormatResponseRequestDto request) throws Exception {
        byte[] tstInfo = TimestampTokenTestUtil.buildTstInfo(
                request.getPolicy(),
                request.getHashAlgorithm().getOid(),
                request.getData(),
                request.getSerialNumber(),
                request.getSigningTime(),
                request.getNonce());
        return TimestampTokenTestUtil.assembleTimestampToken(
                request.getDtbs(),
                request.getSignature(),
                request.getSignatureAlgorithm(),
                request.getCertificateChain(),
                tstInfo,
                request.isIncludeSignerCertificate());
    }

    @Override
    public String getName() {
        return NAME;
    }
}
