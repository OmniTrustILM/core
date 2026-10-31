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
     */
    public static ComputeDtbsRequestDto forFamily(SignatureFamily family, SignatureParametersDto effective,
            DocumentTransferDto document) throws SigningEngineException {
        ComputeDtbsRequestDto request = switch (family) {
            case PADES -> padesRequest(effective, document);
            case XADES -> new XadesComputeDtbsRequestDto();
            case CADES -> new CadesComputeDtbsRequestDto();
            case JADES -> new JadesComputeDtbsRequestDto();
        };
        request.setDocument(document);
        return request;
    }

    /** A PAdES signature is laid out as an incremental revision of the PDF, which no digest can stand in for. */
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
