package com.otilm.core.service.cmp.message.validator.impl;

import com.otilm.api.interfaces.core.cmp.error.CmpProcessingException;
import com.otilm.core.service.cmp.configurations.ConfigurationContext;
import com.otilm.core.service.cmp.message.RevocationReasonCodec;
import com.otilm.core.service.cmp.message.validator.BiValidator;
import java.math.BigInteger;
import java.util.Optional;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.cmp.PKIBody;
import org.bouncycastle.asn1.cmp.PKIFailureInfo;
import org.bouncycastle.asn1.cmp.PKIMessage;
import org.bouncycastle.asn1.cmp.PKIStatus;
import org.bouncycastle.asn1.cmp.PKIStatusInfo;
import org.bouncycastle.asn1.cmp.RevDetails;
import org.bouncycastle.asn1.cmp.RevRepContent;
import org.bouncycastle.asn1.cmp.RevReqContent;
import org.bouncycastle.asn1.crmf.CertTemplate;
import org.bouncycastle.asn1.x509.Extensions;

/**
 * Validate of revocation based messages, {@link RevReqContent} and outgoing {@link RevRepContent}.
 *
 * @see <a href="https://www.rfc-editor.org/rfc/rfc4210#section-5.3.9">Revocation request</a>
 * @see <a href="https://www.rfc-editor.org/rfc/rfc4210#section-5.3.10">Revocation response</a>
 */
public class BodyRevocationValidator extends BaseValidator implements BiValidator<Void, Void> {

    /**
     * <p>
     * Validate of Revocation message (rr)
     * </p>
     *
     * <pre>
     * 		RevReqContent ::= SEQUENCE OF RevDetails
     *
     * 		RevDetails ::= SEQUENCE {
     * 			certDetails         CertTemplate,
     * 			-- allows requester to specify as much as they can about
     * 			-- the cert. for which revocation is requested
     * 			-- (e.g., for cases in which serialNumber is not available)
     * 			crlEntryDetails     Extensions       OPTIONAL
     * 			-- requested crlEntryExtensions
     *                }
     * </pre>
     *
     * @param request of message containing {@link RevReqContent}
     * @throws CmpProcessingException if validation will fail
     * @see <a href="https://www.rfc-editor.org/rfc/rfc4210#appendix-F">Appendix F. Compilable ASN.1 Definitions
     * (rfc4210)</a>
     */
    @Override
    public Void validateIn(PKIMessage request, ConfigurationContext configuration) throws CmpProcessingException {
        assertEqualBodyType(PKIBody.TYPE_REVOCATION_REQ, request);
        ASN1OctetString tid = request.getHeader().getTransactionID();
        RevReqContent content = (RevReqContent) request.getBody().getContent();
        RevDetails[] revDetails = content.toRevDetailsArray();
        checkOneElementInArray(tid, revDetails, "RevDetails");
        CertTemplate certDetails = revDetails[0].getCertDetails();
        checkValueNotNull(tid, certDetails, PKIFailureInfo.badCertId, "certDetails");
        checkValueNotNull(tid, certDetails.getSerialNumber(), PKIFailureInfo.badCertId, "SerialNumber");
        checkValueNotNull(tid, certDetails.getIssuer(), PKIFailureInfo.badCertId, "Issuer");
        // crlEntryDetails / reasonCode are OPTIONAL per RFC 4210 §5.3.9 — a reason-less rr
        // (e.g. `openssl cmp -cmd rr` without -revreason) is valid and defaults to UNSPECIFIED.
        // When a reasonCode is present, reject only the codes the platform cannot represent:
        // out of range, 7 (unused, RFC 5280) and 8 (removeFromCRL — an un-revoke this path
        // cannot perform). The check runs on the raw BigInteger so an oversized value cannot
        // truncate into an in-range code.
        Extensions crlEntryDetails = revDetails[0].getCrlEntryDetails();
        Optional<BigInteger> reasonCode;
        try {
            reasonCode = RevocationReasonCodec.requestedReasonCode(crlEntryDetails);
        } catch (IllegalArgumentException e) {
            // reasonCode extension present but not a well-formed ENUMERATED.
            throw new CmpProcessingException(tid, PKIFailureInfo.badDataFormat, "reasonCode is malformed", e);
        }
        if (reasonCode.isPresent() && RevocationReasonCodec.mapReasonCode(reasonCode.get()).isEmpty()) {
            throw new CmpProcessingException(tid, PKIFailureInfo.badDataFormat,
                    "reasonCode " + reasonCode.get() + " is not supported");
        }

        return null;// validation is ok
    }

    /**
     * <p>
     * Validation of Revocation (response) message (rp)
     * </p>
     *
     * <pre>
     * 		RevRepContent ::= SEQUENCE {
     * 			status       SEQUENCE SIZE (1..MAX) OF PKIStatusInfo,
     * 			-- in same order as was sent in RevReqContent
     * 			revCerts [0] SEQUENCE SIZE (1..MAX) OF CertId
     * 			                                 OPTIONAL,
     * 			-- IDs for which revocation was requested
     * 			-- (same order as status)
     * 			crls     [1] SEQUENCE SIZE (1..MAX) OF CertificateList
     * 			                                 OPTIONAL
     * 			-- the resulting CRLs (there may be more than one)
     *        }
     * </pre>
     *
     * @param response of message containing {@link RevRepContent}
     * @throws CmpProcessingException if validation will fail
     * @see <a href="https://www.rfc-editor.org/rfc/rfc4210#appendix-F">Appendix F. Compilable ASN.1 Definitions
     * (rfc4210)</a>
     */
    @Override
    public Void validateOut(PKIMessage response, ConfigurationContext configuration) throws CmpProcessingException {
        assertEqualBodyType(PKIBody.TYPE_REVOCATION_REP, response);
        ASN1OctetString tid = response.getHeader().getTransactionID();
        RevRepContent content = (RevRepContent) response.getBody().getContent();
        PKIStatusInfo[] statuses = content.getStatus();
        checkOneElementInArray(tid, statuses, "status");

        PKIStatusInfo statusInfo = statuses[0];
        if (statusInfo.getStatus().intValue() == PKIStatus.GRANTED) {
            validatePositiveStatus(tid, statusInfo);
        } else {
            validateNegativeStatus(tid, statusInfo);
        }

        return null;// validation is ok
    }
}
