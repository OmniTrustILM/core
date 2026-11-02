package com.otilm.core.signing.contentsigning.formatting;

import com.otilm.api.model.common.signature.SignatureFamily;
import com.otilm.api.model.common.signature.parameters.SignatureParametersDto;
import com.otilm.api.model.common.signature.parameters.pades.PadesSignatureParametersDto;
import com.otilm.api.model.connector.signatures.contentsigning.cades.CadesComputeDtbsRequestDto;
import com.otilm.api.model.connector.signatures.contentsigning.common.ComputeDtbsRequestDto;
import com.otilm.api.model.connector.signatures.contentsigning.common.DigestOnlyDocumentTransferDto;
import com.otilm.api.model.connector.signatures.contentsigning.common.DocumentTransferDto;
import com.otilm.api.model.connector.signatures.contentsigning.jades.JadesComputeDtbsRequestDto;
import com.otilm.api.model.connector.signatures.contentsigning.pades.PadesComputeDtbsRequestDto;
import com.otilm.api.model.connector.signatures.contentsigning.xades.XadesComputeDtbsRequestDto;
import com.otilm.core.signing.engine.error.SigningEngineException;
import com.otilm.core.signing.engine.error.SigningEngineFailure;

/** {@code computeDtbs} is the one operation with a per-family request subtype, because its parameters differ. */
public final class ComputeDtbsRequests {

    private ComputeDtbsRequests() {
    }

    /**
     * @param effective the permission-checked, merged parameters, or {@code null} when neither side supplied any; only
     * PAdES carries them
     * @throws SigningEngineException when a PAdES run was given a digest alone
     * @throws IllegalStateException when parameters arrive for a family whose connector request has no field for them
     */
    public static ComputeDtbsRequestDto forFamily(SignatureFamily family, SignatureParametersDto effective,
            DocumentTransferDto document) throws SigningEngineException {
        ComputeDtbsRequestDto request = switch (family) {
            case PADES -> padesRequest(effective, document);
            case XADES -> carryingNoParameters(new XadesComputeDtbsRequestDto(), effective);
            case CADES -> carryingNoParameters(new CadesComputeDtbsRequestDto(), effective);
            case JADES -> carryingNoParameters(new JadesComputeDtbsRequestDto(), effective);
        };
        request.setDocument(document);
        return request;
    }

    private static <R extends ComputeDtbsRequestDto> R carryingNoParameters(R request,
            SignatureParametersDto effective) {
        if (effective != null) {
            throw new IllegalStateException("the %s computeDtbs request has no field for %s signature parameters"
                    .formatted(request.getFamily(), effective.getFamily()));
        }
        return request;
    }

    /** A PAdES signature is laid out as an incremental revision of the PDF. No room for digests. */
    private static PadesComputeDtbsRequestDto padesRequest(SignatureParametersDto effective,
            DocumentTransferDto document) throws SigningEngineException {
        if (document instanceof DigestOnlyDocumentTransferDto) {
            throw new SigningEngineException(SigningEngineFailure.INVALID_INPUT,
                    "a PAdES run was given a digest-only document transfer, which cannot carry an incremental revision",
                    "PAdES signing needs the document itself; a digest alone cannot be signed into a PDF");
        }
        PadesComputeDtbsRequestDto request = new PadesComputeDtbsRequestDto();
        request.setSignatureParameters((PadesSignatureParametersDto) effective);
        return request;
    }
}
