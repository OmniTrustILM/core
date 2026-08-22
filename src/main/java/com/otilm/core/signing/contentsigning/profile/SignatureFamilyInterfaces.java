package com.otilm.core.signing.contentsigning.profile;

import com.otilm.api.model.client.connector.v2.ConnectorInterface;
import com.otilm.api.model.common.signature.SignatureFamily;

/** The connector interface that serves a signature family. */
public final class SignatureFamilyInterfaces {

    private SignatureFamilyInterfaces() {
    }

    public static ConnectorInterface of(SignatureFamily family) {
        return switch (family) {
            case PADES -> ConnectorInterface.PADES_FORMATTING;
            case XADES -> ConnectorInterface.XADES_FORMATTING;
            case CADES -> ConnectorInterface.CADES_FORMATTING;
            case JADES -> ConnectorInterface.JADES_FORMATTING;
        };
    }
}
