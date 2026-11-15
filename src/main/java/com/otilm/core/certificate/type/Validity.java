package com.otilm.core.certificate.type;

import java.time.Duration;
import java.time.Instant;

/**
 * The validity period of a certificate. With {@link ValidityPrecision#DATE} both ends are the start of their day in UTC
 * and the period includes the whole last day.
 */
public record Validity(Instant notBefore, Instant notAfter, ValidityPrecision precision) {

    private static final Duration ONE_DAY = Duration.ofDays(1);

    /**
     * The moment the validity ends: the last instant of a period with a time, and the start of the day after the last
     * day of a period with dates only. This is what is stored as the end of the certificate.
     */
    public Instant expiry() {
        return precision == ValidityPrecision.DATE ? notAfter.plus(ONE_DAY) : notAfter;
    }

    public ValidityStatus statusAt(Instant moment) {
        if (moment.isBefore(notBefore)) {
            return ValidityStatus.NOT_YET_VALID;
        }
        boolean expired = precision == ValidityPrecision.DATE ? !moment.isBefore(expiry()) : moment.isAfter(notAfter);
        return expired ? ValidityStatus.EXPIRED : ValidityStatus.VALID;
    }
}
