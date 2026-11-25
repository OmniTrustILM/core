package com.otilm.core.service.renewal;

import java.time.Instant;
import java.util.Objects;

/** A renewal window; its end lies after its start. */
public record Window(Instant start, Instant end) {

    public Window {
        Objects.requireNonNull(start, "start");
        Objects.requireNonNull(end, "end");
        if (!end.isAfter(start)) {
            throw new IllegalArgumentException("Renewal window must end after it starts");
        }
    }
}
