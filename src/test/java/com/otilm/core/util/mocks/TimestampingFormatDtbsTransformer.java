package com.otilm.core.util.mocks;

import com.otilm.api.model.connector.signatures.formatting.FormatDtbsResponseDto;
import com.otilm.api.model.connector.signatures.formatting.TimestampingFormatDtbsRequestDto;
import com.otilm.core.signing.tsa.TimestampTokenTestUtil;
import com.github.tomakehurst.wiremock.http.ResponseDefinition;
import com.github.tomakehurst.wiremock.stubbing.ServeEvent;

/**
 * Phase 1 of the RFC 3161 formatting contract ({@code formatDtbs}), backing
 * {@link TimestampingFormattingConnectorMock#stubFormatDtbs()}: returns the real CMS data-to-be-signed —
 * the DER {@code SignedAttributes} over a TSTInfo built from the request fields.
 */
class TimestampingFormatDtbsTransformer extends TimestampingFormattingTransformer {

    static final String NAME = "tsp-format-dtbs";

    @Override
    public ResponseDefinition transform(ServeEvent serveEvent) {
        try {
            TimestampingFormatDtbsRequestDto request = readRequest(serveEvent, TimestampingFormatDtbsRequestDto.class);

            FormatDtbsResponseDto response = new FormatDtbsResponseDto();
            response.setDtbs(signedAttributesDtbsFor(request));
            return jsonResponse(serveEvent, response);
        } catch (Exception e) {
            throw new IllegalStateException("Failed to format DTBS in WireMock formatting transformer", e);
        }
    }

    private static byte[] signedAttributesDtbsFor(TimestampingFormatDtbsRequestDto request) throws Exception {
        byte[] tstInfo = TimestampTokenTestUtil.buildTstInfo(
                request.getPolicy(),
                request.getHashAlgorithm().getOid(),
                request.getData(),
                request.getSerialNumber(),
                request.getSigningTime(),
                request.getNonce());
        return TimestampTokenTestUtil.buildSignedAttributesDtbs(
                tstInfo,
                request.getCertificateChain().getFirst(),
                request.getSignatureAlgorithm().getDigestAlgorithmIdentifier());
    }

    @Override
    public String getName() {
        return NAME;
    }
}
