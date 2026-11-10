package com.otilm.core.certificate.type;

import java.time.Instant;

/**
 * The validity period of a certificate. With {@link ValidityPrecision#DATE} both ends are the start of their day in
 * UTC.
 */
public record Validity(Instant notBefore, Instant notAfter, ValidityPrecision precision) {
}
