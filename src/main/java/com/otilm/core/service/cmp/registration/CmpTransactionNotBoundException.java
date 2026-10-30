package com.otilm.core.service.cmp.registration;

import com.otilm.api.interfaces.core.cmp.error.CmpProcessingException;
import org.bouncycastle.asn1.ASN1OctetString;

/**
 * A registration-mode follow-up named a transaction its authenticated registration did not open. On the wire it is the
 * same generic registration rejection as any other {@link CmpProcessingException}, but the error handling must not fail
 * the named transaction: the sender was never authorized to act on it, so the request cannot be allowed to poison its
 * state either.
 */
public class CmpTransactionNotBoundException extends CmpProcessingException {

    public CmpTransactionNotBoundException(ASN1OctetString tid, int failureInfo, String errorDetails) {
        super(tid, failureInfo, errorDetails);
    }
}
