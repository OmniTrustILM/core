package com.czertainly.core.signing.tsa.validator;

import com.otilm.api.interfaces.core.tsp.error.TspException;
import com.otilm.api.interfaces.core.tsp.error.TspFailureInfo;

public class TspRequestValidationException extends TspException {

    public TspRequestValidationException(TspFailureInfo failureInfo, String logMessage, String clientMessage) {
        super(failureInfo, logMessage, clientMessage);
    }
}
