package com.otilm.core.util.crl;

import java.math.BigInteger;
import java.security.cert.CRLReason;
import java.util.Date;

/**
 * An entry of a CRL.
 *
 * @param reason the reason code, as the JDK reads it, or {@code null} when the entry carries none
 */
public record RevokedCertificate(BigInteger serialNumber, Date revocationDate, CRLReason reason) {
}
