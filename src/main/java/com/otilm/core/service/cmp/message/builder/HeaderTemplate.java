package com.otilm.core.service.cmp.message.builder;

import org.bouncycastle.asn1.ASN1GeneralizedTime;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.cmp.InfoTypeAndValue;
import org.bouncycastle.asn1.cmp.PKIHeader;
import org.bouncycastle.asn1.x509.GeneralName;

/**
 * To allow to provide values for {@link PKIHeader} dynamically
 *
 * <pre>
 *     PKIHeader ::= SEQUENCE {
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
 * </pre>
 */
public interface HeaderTemplate {
    /**
     * @return CMP version to be used in CMP header.
     */
    int getPvno();

    /**
     * @return Sender to be used in CMP header
     */
    GeneralName getSender();

    /**
     * @return SenderNonce to be used in CMP header
     */
    ASN1OctetString getSenderNonce();

    /**
     * @return Recipient to be used in CMP header
     */
    GeneralName getRecipient();

    /**
     * @return RecipNonce to be used in CMP header
     */
    ASN1OctetString getRecipNonce();

    /**
     * @return time when message is processing
     */
    ASN1GeneralizedTime getMessageTime();

    /**
     * @return TransactionID to be used in CMP header
     */
    ASN1OctetString getTransactionID();

    /**
     * @return GeneralInfo (ImplicitConfirm, ConfirmWaitTime) to be used in CMP header
     */
    InfoTypeAndValue[] getGeneralInfo();
}
