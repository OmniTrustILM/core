package com.otilm.core.service.cmp.message;

import com.otilm.api.model.core.authority.CertificateRevocationReason;
import java.math.BigInteger;
import java.util.Optional;
import org.bouncycastle.asn1.ASN1Enumerated;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.Extensions;

/**
 * Shared parsing of the CMP revocation reason carried in {@code rr} crlEntryDetails, used by both
 * {@link com.otilm.core.service.cmp.message.validator.impl.BodyRevocationValidator} (to reject codes the platform
 * cannot represent) and {@link com.otilm.core.service.cmp.message.handler.RevocationMessageHandler} (to map the code to
 * a {@link CertificateRevocationReason}). Keeping the two in one place stops the parse and the accepted-code set from
 * drifting apart.
 */
public final class RevocationReasonCodec {

    /** Highest defined CRLReason code; see {@link CertificateRevocationReason}. */
    private static final BigInteger MAX_REASON_CODE = BigInteger.TEN;

    private RevocationReasonCodec() {
    }

    /**
     * The revocation reason code the client requested.
     *
     * @return the raw reasonCode, or empty when the rr specifies none — crlEntryDetails is absent (valid per RFC 4210
     * §5.3.9), or present without a reasonCode extension.
     */
    public static Optional<BigInteger> requestedReasonCode(Extensions crlEntryDetails) {
        if (crlEntryDetails == null) {
            return Optional.empty();
        }
        Extension reasonCodeExt = crlEntryDetails.getExtension(Extension.reasonCode);
        if (reasonCodeExt == null) {
            return Optional.empty();
        }
        return Optional.of(ASN1Enumerated.getInstance(reasonCodeExt.getParsedValue()).getValue());
    }

    /**
     * Map a raw reasonCode to a reason without narrowing first — an out-of-range or oversized value (one that would
     * truncate through {@code longValue()}/{@code intValue()} into a valid code) is rejected on the raw
     * {@link BigInteger}.
     *
     * @return the mapped reason, or empty when the code is out of range or otherwise unmappable (7 unused per RFC 5280,
     * 8 removeFromCRL).
     */
    public static Optional<CertificateRevocationReason> mapReasonCode(BigInteger reasonCode) {
        if (reasonCode.signum() < 0 || reasonCode.compareTo(MAX_REASON_CODE) > 0) {
            return Optional.empty();
        }
        return Optional.ofNullable(CertificateRevocationReason.fromReasonCode(reasonCode.intValueExact()));
    }
}
