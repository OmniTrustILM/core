package com.czertainly.core.util.serialnumber;

public class ClockDriftException extends SerialNumberGenerationException {

    public ClockDriftException(String message) {
        super(message);
    }
}
