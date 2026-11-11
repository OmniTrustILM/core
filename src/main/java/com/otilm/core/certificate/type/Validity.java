package com.otilm.core.certificate.type;

import java.time.Duration;
import java.time.Instant;

/**
 * The validity period of a certificate. With {@link ValidityPrecision#DATE} both ends are the start of their day in UTC
 * and the period includes the whole last day.
 */
public record Validity(Instant notBefore, Instant notAfter, ValidityPrecision precision) {

    private static final Duration ONE_DAY = Duration.ofDays(1);

    public ValidityStatus statusAt(Instant moment) {
        if (moment.isBefore(notBefore)) {
            return ValidityStatus.NOT_YET_VALID;
        }
        Instant end = precision == ValidityPrecision.DATE ? notAfter.plus(ONE_DAY) : notAfter;
        return moment.isAfter(end) ? ValidityStatus.EXPIRED : ValidityStatus.VALID;
    }
}
