package com.czertainly.core.util.serialnumber;

import com.czertainly.api.exception.PlatformException;

public class SerialNumberGenerationException extends RuntimeException implements PlatformException {

    public SerialNumberGenerationException(String message) {
        super(message);
    }
}
