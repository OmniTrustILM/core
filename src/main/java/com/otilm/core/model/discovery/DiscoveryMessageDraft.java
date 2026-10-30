package com.otilm.core.model.discovery;

import com.otilm.api.model.core.discovery.DiscoveryMessageSeverity;

/**
 * One problem a producer wants recorded against a run, before the writer bounds and aggregates it.
 *
 * <p>
 * <b>{@code message} names the kind of problem and nothing about the occurrence</b> — not a count, not a certificate,
 * not a host, not a reference. Anything run-specific makes every message distinct, which turns aggregation back into
 * accumulation and buries a run's first and most useful entry under its ten thousandth. The count in particular belongs
 * in {@code occurrences}, which adds across every batch reporting the same thing.
 *
 * <p>
 * Where a staged row exists the detail is relocated, not lost: why one certificate failed to <em>import</em> is on that
 * certificate's own row ({@code discovery_certificate.processed_error}). Failures before a row exists — staging, an
 * invalid payload, a missing sequence — name what they hit in the application log only, which is where they were before
 * this log existed. These messages are a bounded summary above it rather than a replacement for it: naming every
 * occurrence here is what would make the log too long to read.
 *
 * @param occurrences how many times this producer saw the problem in the work it is reporting on
 */
public record DiscoveryMessageDraft(DiscoveryMessageSeverity severity, String code, String message, long occurrences) {

    public DiscoveryMessageDraft {
        if (occurrences < 1) {
            throw new IllegalArgumentException("A discovery run message records at least one occurrence");
        }
        // Refused here rather than at the insert: code is the one field taken verbatim from outside the platform,
        // and both columns are NOT NULL, so a connector that omits its code would otherwise roll back whatever
        // transaction the append had joined -- a whole drained page, for a field this can simply reject.
        if (code == null || code.isBlank()) {
            throw new IllegalArgumentException("A discovery run message needs a code naming the kind of problem");
        }
        if (message == null || message.isBlank()) {
            throw new IllegalArgumentException("A discovery run message needs text for a person to read");
        }
    }

    public DiscoveryMessageDraft(DiscoveryMessageSeverity severity, DiscoveryMessageCode code, String message,
            long occurrences) {
        this(severity, code.code(), message, occurrences);
    }
}
