package com.otilm.core.util.serialnumber;

public class ClockDriftException extends SerialNumberGenerationException {

    public ClockDriftException(String message) {
        super(message);
    }
}
