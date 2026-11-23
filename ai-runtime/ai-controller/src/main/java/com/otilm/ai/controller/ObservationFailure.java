package com.otilm.ai.controller;

/** Fixed failure boundary; API/credential contents and raw causes are never attached. */
public final class ObservationFailure extends RuntimeException {
    public ObservationFailure() {
        super("OBSERVATION_UNAVAILABLE", null, false, false);
    }
}
