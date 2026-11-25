package com.otilm.core.service.renewal;

import com.otilm.api.model.core.certificate.RenewalWindowSource;
import java.time.Instant;
import java.util.Objects;

/** The stored renewal state of a certificate; without a window, the window fields and the source are null. */
public record RenewalState(Instant windowStart, Instant windowEnd, String explanationUrl, RenewalWindowSource source,
        Instant updatedAt, boolean advanced) {

    public static final RenewalState NONE = new RenewalState(null, null, null, null, null, false);

    public boolean hasWindow() {
        return windowStart != null;
    }

    /** Whether both states hold the same window, explanation and source, whenever and however they were set. */
    public boolean sameWindowAs(RenewalState other) {
        return Objects.equals(windowStart, other.windowStart) && Objects.equals(windowEnd, other.windowEnd)
                && Objects.equals(explanationUrl, other.explanationUrl) && source == other.source;
    }
}
