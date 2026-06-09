package com.czertainly.core.util.serialnumber;

import com.otilm.api.exception.PlatformException;

public class SerialNumberGenerationException extends RuntimeException implements PlatformException {

    public SerialNumberGenerationException(String message) {
        super(message);
    }
}
