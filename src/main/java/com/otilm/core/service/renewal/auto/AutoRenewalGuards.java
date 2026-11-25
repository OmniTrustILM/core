package com.otilm.core.service.renewal.auto;

import com.otilm.api.model.core.certificate.AutoRenewalMode;
import com.otilm.api.model.core.certificate.CertificateState;
import java.time.Duration;
import java.time.Instant;

/**
 * The guards of automatic renewal as pure functions. The common guards decide whether a firing renews the certificate
 * at all; the unit guards decide whether one unit of work (the certificate when the platform holds its key, or one
 * key-generating location) starts a renewal now.
 */
public final class AutoRenewalGuards {

    /** How long a claimed firing blocks the next one; a node that dies after claiming frees it after this lease. */
    public static final Duration IN_FLIGHT_LEASE = Duration.ofMinutes(15);

    private static final Duration FIRST_BACKOFF = Duration.ofHours(1);
    private static final Duration SECOND_BACKOFF = Duration.ofHours(6);
    private static final Duration LAST_BACKOFF = Duration.ofHours(24);

    private AutoRenewalGuards() {
    }

    /** Why a firing does not renew the certificate. */
    public enum CommonSkip {
        DISABLED,
        NO_MODE,
        NO_WINDOW,
        NOT_DUE
    }

    /** The certificate's automatic renewal state as a firing sees it. */
    public record CommonInput(boolean enabled, AutoRenewalMode mode, Instant renewAt, Instant windowStart,
            Instant windowEnd) {
    }

    /**
     * The outcome of the common guards: a skip reason, or none when the firing proceeds. {@code renewAt} is the stored
     * renewal time or the one chosen now, and null when a guard before the choice skipped.
     */
    public record GuardResult(CommonSkip skip, Instant renewAt) {

        public boolean proceeds() {
            return skip == null;
        }
    }

    /** The state of the successor a unit of work started. */
    public enum SuccessorStatus {
        NONE,
        IN_FLIGHT,
        ISSUED,
        FAILED;

        /** Reads the state of a successor; a successor that no longer exists is read as failed. */
        public static SuccessorStatus of(CertificateState state) {
            if (state == null) {
                return FAILED;
            }
            return switch (state) {
                case ISSUED, REVOKED -> ISSUED;
                case FAILED, REJECTED -> FAILED;
                default -> IN_FLIGHT;
            };
        }
    }

    /**
     * One unit of work: whether it is completed, the state of its successor, whether another actor's renewal of the
     * certificate is under way, and its failed attempts and backoff.
     */
    public record UnitInput(boolean completed, SuccessorStatus successor, boolean foreignRenewal, int attempt,
            Instant notBefore, int maxAttempts) {
    }

    /** What a unit of work does on this firing; every outcome but {@code START} is a skip. */
    public enum UnitOutcome {
        START,
        COMPLETED,
        MARK_COMPLETED,
        IN_FLIGHT,
        FOREIGN_RENEWAL,
        MAX_ATTEMPTS,
        BACKOFF
    }

    /**
     * A counted failure: the new attempt count and backoff. {@code limitReached} is set only when this failure brings
     * the count to the limit.
     */
    public record FailureCount(int attempt, Instant notBefore, boolean limitReached) {
    }

    /**
     * The outcome of the unit guards. {@code failure} is set when the unit's successor was found failed, rejected or
     * gone: the caller stores the count and clears the successor.
     */
    public record UnitGuardResult(UnitOutcome outcome, FailureCount failure) {
    }

    /**
     * Applies the common guards in order: automatic renewal enabled, a mode that can renew, a renewal time (chosen
     * uniformly in [max(now, start), end] when none is stored, or now when the window has ended), and that time
     * reached.
     *
     * @param random a draw in [0, 1) that places a newly chosen renewal time in the window
     */
    public static GuardResult common(CommonInput input, Instant now, double random) {
        if (!input.enabled()) {
            return new GuardResult(CommonSkip.DISABLED, null);
        }
        if (input.mode() == AutoRenewalMode.NONE) {
            return new GuardResult(CommonSkip.NO_MODE, null);
        }
        Instant renewAt = input.renewAt();
        if (renewAt == null) {
            if (input.windowStart() == null || input.windowEnd() == null) {
                return new GuardResult(CommonSkip.NO_WINDOW, null);
            }
            renewAt = chooseRenewAt(input.windowStart(), input.windowEnd(), now, random);
        }
        if (now.isBefore(renewAt)) {
            return new GuardResult(CommonSkip.NOT_DUE, renewAt);
        }
        return new GuardResult(null, renewAt);
    }

    /** Whether a firing claimed at {@code startedAt} still holds the certificate. */
    public static boolean markerHeld(Instant startedAt, Instant now) {
        return startedAt != null && now.isBefore(startedAt.plus(IN_FLIGHT_LEASE));
    }

    /**
     * Applies the unit guards in order: not completed; no successor in flight (an issued one completes the unit, a
     * failed, rejected or gone one counts a failure and is cleared); no renewal by another actor; attempts below the
     * limit; backoff over.
     */
    public static UnitGuardResult unit(UnitInput input, Instant now) {
        if (input.completed()) {
            return new UnitGuardResult(UnitOutcome.COMPLETED, null);
        }
        FailureCount failure = null;
        int attempt = input.attempt();
        Instant notBefore = input.notBefore();
        switch (input.successor()) {
            case ISSUED -> {
                return new UnitGuardResult(UnitOutcome.MARK_COMPLETED, null);
            }
            case IN_FLIGHT -> {
                return new UnitGuardResult(UnitOutcome.IN_FLIGHT, null);
            }
            case FAILED -> {
                failure = countFailure(attempt, input.maxAttempts(), now);
                attempt = failure.attempt();
                notBefore = failure.notBefore();
            }
            case NONE -> {
                // nothing started yet, or the last start was cleared
            }
        }
        UnitOutcome outcome;
        if (input.foreignRenewal()) {
            outcome = UnitOutcome.FOREIGN_RENEWAL;
        } else if (attempt >= input.maxAttempts()) {
            outcome = UnitOutcome.MAX_ATTEMPTS;
        } else if (notBefore != null && now.isBefore(notBefore)) {
            outcome = UnitOutcome.BACKOFF;
        } else {
            outcome = UnitOutcome.START;
        }
        return new UnitGuardResult(outcome, failure);
    }

    /** Counts one more failed renewal and backs off by 1 h, 6 h, then 24 h. */
    public static FailureCount countFailure(int previousAttempts, int maxAttempts, Instant now) {
        int attempt = previousAttempts + 1;
        boolean limitReached = previousAttempts < maxAttempts && attempt >= maxAttempts;
        return new FailureCount(attempt, now.plus(backoff(attempt)), limitReached);
    }

    private static Duration backoff(int attempt) {
        if (attempt <= 1) {
            return FIRST_BACKOFF;
        }
        return attempt == 2 ? SECOND_BACKOFF : LAST_BACKOFF;
    }

    private static Instant chooseRenewAt(Instant windowStart, Instant windowEnd, Instant now, double random) {
        if (!now.isBefore(windowEnd)) {
            return now;
        }
        Instant earliest = windowStart.isAfter(now) ? windowStart : now;
        long spanMillis = Duration.between(earliest, windowEnd).toMillis();
        return earliest.plusMillis((long) (spanMillis * random));
    }
}
