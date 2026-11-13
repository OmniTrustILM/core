package com.otilm.core.certificate.type;

import com.otilm.api.exception.ValidationException;
import com.otilm.api.model.core.certificate.CertificateOperation;

/**
 * No handler is registered for a certificate type, a type does not support an operation, or an authority does not issue
 * a type.
 */
public class UnsupportedCertificateTypeException extends ValidationException {

    public UnsupportedCertificateTypeException(String message) {
        super(message);
    }

    public static UnsupportedCertificateTypeException unknownType(String typeCode) {
        return new UnsupportedCertificateTypeException("Unsupported certificate type: " + typeCode);
    }

    public static UnsupportedCertificateTypeException unsupportedOperation(String typeCode,
            CertificateOperation operation) {
        return new UnsupportedCertificateTypeException(
                "The operation " + operation + " is not supported for certificates of type " + typeCode);
    }

    public static UnsupportedCertificateTypeException notIssuedByAuthority(String typeCode, String raProfileName) {
        return new UnsupportedCertificateTypeException("The authority of the RA profile " + raProfileName
                + " does not issue certificates of type " + typeCode);
    }
}
