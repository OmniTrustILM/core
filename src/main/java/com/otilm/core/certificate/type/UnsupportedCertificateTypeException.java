package com.otilm.core.certificate.type;

import com.otilm.api.model.core.certificate.CertificateOperation;

/** No handler is registered for a certificate type, or a type does not support an operation. */
public class UnsupportedCertificateTypeException extends CertificateTypeHandlerException {

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
}
