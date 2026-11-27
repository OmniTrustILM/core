package com.otilm.core.certificate.type;

import com.otilm.api.exception.ValidationException;
import com.otilm.api.model.core.certificate.CertificateOperation;
import com.otilm.api.model.core.enums.CertificateRequestFormat;

/** A certificate type cannot do what was asked of it; the message names the type. */
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
                "The operation " + operation.getLabel() + " is not supported for certificates of type " + typeCode);
    }

    public static UnsupportedCertificateTypeException unsupportedRequestFormat(String typeCode,
            CertificateRequestFormat format) {
        return new UnsupportedCertificateTypeException(
                "The request format " + format.getCode() + " is not supported for certificates of type " + typeCode);
    }

    public static UnsupportedCertificateTypeException notStored(String typeCode) {
        return new UnsupportedCertificateTypeException("Certificates of type " + typeCode + " cannot be stored");
    }

    public static UnsupportedCertificateTypeException notIssuedByAuthority(String typeCode, String raProfileName) {
        return new UnsupportedCertificateTypeException("The authority of the RA profile " + raProfileName
                + " does not issue certificates of type " + typeCode);
    }
}
