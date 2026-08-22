package com.otilm.core.signing.contentsigning.formatting;

import com.otilm.api.model.common.signature.SignatureFamily;
import com.otilm.api.model.connector.signatures.contentsigning.cades.CadesComputeDtbsRequestDto;
import com.otilm.api.model.connector.signatures.contentsigning.common.ComputeDtbsRequestDto;
import com.otilm.api.model.connector.signatures.contentsigning.jades.JadesComputeDtbsRequestDto;
import com.otilm.api.model.connector.signatures.contentsigning.pades.PadesComputeDtbsRequestDto;
import com.otilm.api.model.connector.signatures.contentsigning.xades.XadesComputeDtbsRequestDto;

/** {@code computeDtbs} is the one operation with a per-family request subtype, because its parameters differ. */
public final class ComputeDtbsRequests {

    private ComputeDtbsRequests() {
    }

    public static ComputeDtbsRequestDto forFamily(SignatureFamily family) {
        return switch (family) {
            case PADES -> new PadesComputeDtbsRequestDto();
            case XADES -> new XadesComputeDtbsRequestDto();
            case CADES -> new CadesComputeDtbsRequestDto();
            case JADES -> new JadesComputeDtbsRequestDto();
        };
    }
}
