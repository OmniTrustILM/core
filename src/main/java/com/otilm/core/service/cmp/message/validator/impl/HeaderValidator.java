package com.otilm.core.service.cmp.message.validator.impl;

import com.otilm.api.interfaces.core.cmp.error.CmpBaseException;
import com.otilm.api.interfaces.core.cmp.error.CmpProcessingException;
import com.otilm.core.service.cmp.configurations.ConfigurationContext;
import com.otilm.core.service.cmp.message.validator.Validator;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.cmp.*;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Transactional;

import java.util.Objects;

/**
 * <pre>
 *      PKIHeader ::= SEQUENCE {
 *          pvno                INTEGER     { cmp1999(1), cmp2000(2) },
 *          sender              GeneralName,
 *          recipient           GeneralName,
 *          messageTime     [0] GeneralizedTime         OPTIONAL,
 *          protectionAlg   [1] AlgorithmIdentifier     OPTIONAL,
 *          senderKID       [2] KeyIdentifier           OPTIONAL,
 *          recipKID        [3] KeyIdentifier           OPTIONAL,
 *          transactionID   [4] OCTET STRING            OPTIONAL,
 *          senderNonce     [5] OCTET STRING            OPTIONAL,
 *          recipNonce      [6] OCTET STRING            OPTIONAL,
 *          freeText        [7] PKIFreeText             OPTIONAL,
 *          generalInfo     [8] SEQUENCE SIZE (1..MAX) OF
 *                              InfoTypeAndValue     OPTIONAL
 *      }
 *      PKIFreeText ::= SEQUENCE SIZE (1..MAX) OF UTF8String
 * </pre>
 *
 * @see <a href="https://www.rfc-editor.org/rfc/rfc4210#section-5.1.1">PKI Message header</a>
 */
@Component
@Transactional
public class HeaderValidator extends BaseValidator implements Validator<PKIMessage, Void> {

    @Override
    public Void validate(PKIMessage message, ConfigurationContext configuration) throws CmpBaseException {
        if (Objects.isNull(message)) {
            throw new CmpProcessingException(PKIFailureInfo.badDataFormat,
                    "message cannot be null");
        }
        if (Objects.isNull(message.getHeader())) {
            throw new CmpProcessingException(PKIFailureInfo.badDataFormat,
                    "header cannot be null");
        }
        ASN1OctetString tid = message.getHeader().getTransactionID();
        try {
            PKIHeader header = message.getHeader();
            checkValueNotNull(tid, header, PKIFailureInfo.badDataFormat, "header");
            ASN1Integer pvno = header.getPvno();
            checkValueNotNull(tid, pvno, PKIFailureInfo.unsupportedVersion, "pvno");
            long versionNumber = pvno.longValueExact();
            if (versionNumber != PKIHeader.CMP_2000) {
                throw new CmpProcessingException(PKIFailureInfo.unsupportedVersion,
                        "version " + versionNumber + " not supported");
            }
            checkValueNotNull(tid, header.getSender(), PKIFailureInfo.badDataFormat, "sender");
            checkValueNotNull(tid, header.getRecipient(), PKIFailureInfo.badDataFormat, "recipient");
            checkMinimalLength(tid, header.getTransactionID(), 16, "transactionID");
            checkMinimalLength(tid, header.getSenderNonce(), 16, "senderNonce");

            /*
             * The protectionAlg field specifies the algorithm used to protect the
             * message.  If no protection bits are supplied (note that PKIProtection
             * is OPTIONAL) then this field MUST be omitted; if protection bits are
             * supplied, then this field MUST be supplied.
             *
             * @see https://www.rfc-editor.org/rfc/rfc4210#section-5.1.1
             *
             * if not null, it will in form defined in:
             * @see https://www.rfc-editor.org/rfc/rfc4210#appendix-D.2
             */
            if (message.getProtection() != null) {
                checkValueNotNull(tid, header.getProtectionAlg(),
                        PKIFailureInfo.badDataFormat, "protectionAlg");
            }

            return null;//header is ok
        } catch (CmpProcessingException ex) {
            throw remapException(tid, message.getBody().getType(), ex);
        } catch (Throwable thr) {
            throw new CmpProcessingException(tid, PKIFailureInfo.systemFailure,
                    "header validator: internal error - " + thr.getLocalizedMessage());
        }
    }

}
