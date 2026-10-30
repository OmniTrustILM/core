package com.otilm.core.api.tsp.parser;

import com.otilm.api.interfaces.core.tsp.error.TspException;
import com.otilm.api.interfaces.core.tsp.error.TspFailureInfo;

public class TspRequestParsingException extends TspException {

    TspRequestParsingException(TspFailureInfo failureInfo, String logMessage, String clientMessage) {
        super(failureInfo, logMessage, clientMessage);
    }

}
