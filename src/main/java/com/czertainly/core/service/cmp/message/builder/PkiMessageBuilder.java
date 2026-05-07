package com.czertainly.core.service.cmp.message.builder;

import com.czertainly.api.interfaces.core.cmp.error.CmpBaseException;
import com.czertainly.api.interfaces.core.cmp.error.CmpProcessingException;
import com.czertainly.core.service.cmp.configurations.ConfigurationContext;
import com.czertainly.core.service.cmp.message.PkiMessageDumper;
import com.czertainly.core.service.cmp.message.protection.ProtectionStrategy;
import com.czertainly.core.util.CertificateUtil;
import org.bouncycastle.asn1.ASN1GeneralizedTime;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.DERBitString;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.cmp.*;
import org.bouncycastle.asn1.x500.RDN;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.GeneralName;

import java.util.Collections;
import java.util.Date;
import java.util.List;
import java.util.stream.Stream;

import static com.czertainly.core.util.NullUtil.*;

/**
 * Builder pattern implementation to create specific types of {@link PKIMessage}.
 */
public class PkiMessageBuilder {

    /**
     * see rfc4210, D.1.4
     * <p>A "special" X.500 DN is called the "NULL-DN"; this means a DN
     * containing a zero-length SEQUENCE OF RelativeDistinguishedNames
     * (its DER encoding is then '3000'H).</p>
     *
     * @see <a href="https://www.rfc-editor.org/rfc/rfc4210#appendix-D.1">General Rules for Interpretation of These Profiles at rfcx4210</a>
     */
    public static final GeneralName NULL_DN = new GeneralName(new X500Name(new RDN[0]));
    /**
     * Mandatory field, {@link PKIHeader}
     *
     * @see <a href="https://www.rfc-editor.org/rfc/rfc4210#section-5.1">Overall of PKI Message (header is mandatory)</a>
     * @see <a href="https://www.rfc-editor.org/rfc/rfc4210#section-5.1.1">PKI header structure</a>
     */
    private PKIHeader pkiHeader;
    /**
     * Mandatory field, {@link PKIBody}
     *
     * @see <a href="https://www.rfc-editor.org/rfc/rfc4210#section-5.1">Overall of PKI Message (header is mandatory)</a>
     * @see <a href="https://www.rfc-editor.org/rfc/rfc4210#section-5.1.2">PKI body structure</a>
     */
    private PKIBody pkiBody;
    /**
     * <p>Optional field, extraCerts   [1] SEQUENCE SIZE (1..MAX) OF CMPCertificate OPTIONAL</p>
     *
     * <p>The extraCerts field can contain certificates that may be useful to
     * the recipient.  For example, this can be used by a CA or RA to
     * present an end entity with certificates that it needs to verify its
     * own new certificate (if, for example, the CA that issued the end
     * entity's certificate is not a root CA for the end entity).  Note that
     * this field does not necessarily contain a certification path; the
     * recipient may have to sort, select from, or otherwise process the
     * extra certificates in order to use them.</p>
     *
     * @see <a href="https://www.rfc-editor.org/rfc/rfc4210#section-5.1">Overall of PKI Message (extraCert is OPTIONAL)</a>
     */
    private CMPCertificate[] extraCerts;

    private final ConfigurationContext config;
    private final ProtectionStrategy protectionStrategy;
    private ASN1OctetString transactionID;

    public PkiMessageBuilder(ConfigurationContext configuration) throws CmpBaseException {
        this.config = configuration;
        this.protectionStrategy = configuration.getProtectionStrategy();
    }

    /**
     * <pre>
     *    PKIHeader ::= SEQUENCE {
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
     *
     * @param template wrapper which keeps/creates values for build of {@link PKIHeader}
     * @return builder itself
     */
    public PkiMessageBuilder addHeader(HeaderTemplate template) throws CmpBaseException {
        GeneralName recipient = computeDefaultIfNull(config.getRecipient(), template::getRecipient);
        GeneralName sender = computeDefaultIfNull(protectionStrategy.getSender(), template::getSender);

        PKIHeaderBuilder headerBuilder = new PKIHeaderBuilder(
                template.getPvno(),                                            // -- pvno         , int
                defaultIfNull(sender, NULL_DN),                                // -- sender       , GeneralName
                defaultIfNull(recipient, NULL_DN));                            // -- recipient    , GeneralName
        headerBuilder.setMessageTime(template.getMessageTime());               // -- messageTime  , GeneralizedTime
        headerBuilder.setProtectionAlg(protectionStrategy.getProtectionAlg()); // -- protectionAlg, AlgorithmIdentifier
        headerBuilder.setSenderKID(protectionStrategy.getSenderKID());         // -- senderKID    , KeyIdentifier
        // recipKID                                                            // -- recipKID     , KeyIdentifier
        headerBuilder.setTransactionID(template.getTransactionID());           // -- transactionID, OCTET STRING
        headerBuilder.setSenderNonce(template.getSenderNonce());               // -- senderNonce  , OCTET STRING
        headerBuilder.setRecipNonce(template.getRecipNonce());                 // -- recipNonce   , OCTET STRING
        // freeText                                                            // -- freeText     , OCTET STRING
        headerBuilder.setGeneralInfo(template.getGeneralInfo());               // -- generalInfo  , InfoTypeAndValue SEQUENCE (1..MAX)

        this.pkiHeader = headerBuilder.build();
        this.transactionID = template.getTransactionID();
        return this;
    }

    /**
     * @param pkiBody which will be added to final {@link PKIMessage}
     * @return builder itself (for flow-api)
     * @see <a href="https://www.rfc-editor.org/rfc/rfc4210#section-5.1">Overall of PKI Message (Body is mandatory)</a>
     * @see <a href="https://www.rfc-editor.org/rfc/rfc4210#section-5.1.2">PKI body structure</a>
     */
    public PkiMessageBuilder addBody(PKIBody pkiBody) throws CmpProcessingException {
        if (pkiBody == null) {
            throw new CmpProcessingException(transactionID, PKIFailureInfo.systemFailure, "PKI body is null");
        }
        this.pkiBody = pkiBody;
        return this;
    }

    /**
     * <p>The extraCerts field can contain certificates that may be useful to
     * the recipient.  For example, this can be used by a CA or RA to
     * present an end entity with certificates that it needs to verify its
     * own new certificate (if, for example, the CA that issued the end
     * entity's certificate is not a root CA for the end entity).  Note that
     * this field does not necessarily contain a certification path; the
     * recipient may have to sort, select from, or otherwise process the
     * extra certificates in order to use them.</p>
     * Location:
     * (optional) PKIMessage.caPubs (at same level as header/body)
     *
     * @param chainOfCertificates chain of certificates for extraCerts
     * @return builder itself
     * @see <a href="https://www.rfc-editor.org/rfc/rfc4210#section-5.1">PKI Message header</a>
     */
    public PkiMessageBuilder addExtraCerts(List<CMPCertificate> chainOfCertificates) {
        try {
            //noinspection SuspiciousToArrayCall
            extraCerts = Stream.concat(
                            defaultIfNull(protectionStrategy.getProtectingExtraCerts(), Collections.emptyList()).stream(),
                            defaultIfNull(chainOfCertificates, Collections.emptyList()).stream()
                    ).distinct()
                    .toArray(CMPCertificate[]::new);
        } catch (Exception e) {
            throw new IllegalStateException("problem add extra certificates", e);
        }

        if (config.dumpSigning()) {
            PkiMessageDumper.dumpSingerCertificate(
                    "builder",
                    null,
                    extraCerts);
        }

        return this;
    }

    public PKIMessage build() {
        if (pkiHeader == null) {
            throw new IllegalStateException(
                    "TID=" + transactionID + " | response message cannot be without PKIHeader");
        }
        if (pkiBody == null) {
            throw new IllegalStateException(
                    "TID=" + transactionID + " | response message cannot be without PKIBody");
        }
        DERBitString protection;
        try {
            protection = protectionStrategy.createProtection(pkiHeader, pkiBody);
        } catch (Exception e) {
            throw new IllegalStateException(
                    "TID=" + transactionID + " | response message cannot be protected", e);
        }
        return new PKIMessage(
                pkiHeader,
                pkiBody,
                protection,
                (extraCerts == null || extraCerts.length == 0) ? null : extraCerts);
    }

    //------------------------------------------------------------------------------------------------------
    //  HELPER METHODS
    //------------------------------------------------------------------------------------------------------

    /**
     * Basic (most message use this way) {@link PKIHeader} template object (it means that
     * it keeps or create pki header values for another processing).
     *
     * @param message ability to get/create value from given {@link PKIMessage}
     * @return template object with values for {@link HeaderTemplate}
     */
    public static HeaderTemplate buildBasicHeaderTemplate(PKIMessage message) {
        return new HeaderTemplate() {
            @Override
            public int getPvno() {
                return message.getHeader().getPvno().intValueExact();
            }

            /**
             * The sender field contains the name of the sender of the PKIMessage.
             *    This name (in conjunction with senderKID, if supplied) should be
             *    sufficient to indicate the key to use to verify the protection on the
             *    message.  If nothing about the sender is known to the sending entity
             *    (e.g., in the init. req. message, where the end entity may not know
             *    its own Distinguished Name (DN), e-mail name, IP address, etc.), then
             *    the "sender" field MUST contain a "NULL" value; that is, the SEQUENCE
             *    OF relative distinguished names is of zero length.
             *
             * @return null
             *
             * @see <a href="https://www.rfc-editor.org/rfc/rfc4210#section-5.1.1">[1]PKIHeader element</a>
             */
            @Override
            public GeneralName getSender() {
                return null;
            }

            /**
             * The senderNonce will typically be 128 bits of
             *      (pseudo-) random data generated by the sender...
             *      in the transaction.
             *
             * @see <a href="https://www.rfc-editor.org/rfc/rfc4210#section-5.1.1">[1]PKIHeader element</a>
             */
            @Override
            public ASN1OctetString getSenderNonce() {
                return new DEROctetString(CertificateUtil.generateRandomBytes(16));
            }

            /**
             * <p>The recipient field contains the name of the recipient of the
             *    PKIMessage.  This name (in conjunction with recipKID, if supplied)
             *    should be usable to verify the protection on the message.
             *    see, link [1] below.</p>
             *
             * <pre>
             * ir - CA name
             *      -- the name of the CA who is being asked to produce a certificate
             * ip - CA name
             *      -- the name of the CA who produced the message
             * certConf - CA name
             *      -- the name of the CA who was asked to produce a certificate
             * pkiConf - present
             *      -- sender name from certConf
             * see, link [2] below
             * </pre>
             *
             * @return name of recipient message
             *
             * @see <a href="https://www.rfc-editor.org/rfc/rfc4210#section-5.1.1">[1]PKIHeader element</a>
             * @see <a href="https://www.rfc-editor.org/rfc/rfc4210#appendix-D.4">[2]Initial Registration/Certification (Basic Authenticated Scheme)</a>
             */
            @Override
            public GeneralName getRecipient() {
                return message.getHeader().getSender();
            }

            /**
             * whereas the recipNonce
             *    is copied from the senderNonce of the previous message in the
             *    transaction.
             *
             * @see <a href="https://www.rfc-editor.org/rfc/rfc4210#section-5.1.1">[1]PKIHeader element</a>
             */
            @Override
            public ASN1OctetString getRecipNonce() {
                return message.getHeader().getSenderNonce();
            }

            @Override
            public ASN1GeneralizedTime getMessageTime() {
                return new ASN1GeneralizedTime(new Date());
            }

            @Override
            public ASN1OctetString getTransactionID() {
                return message.getHeader().getTransactionID();
            }

            @Override
            public InfoTypeAndValue[] getGeneralInfo() {
                return message.getHeader().getGeneralInfo();
            }
        };
    }

    public static PKIBody createIpCpKupBody(PKIBody body, CertResponse[] response,
                                            CMPCertificate[] caPubs) throws CmpProcessingException {
        int bodyType = body.getType();
        switch (bodyType) {
            case PKIBody.TYPE_INIT_REQ:
            case PKIBody.TYPE_CERT_REQ:
            case PKIBody.TYPE_KEY_UPDATE_REQ:
                break;
            default:
                throw new CmpProcessingException(PKIFailureInfo.systemFailure,
                        "cannot generate response for given type, type=" + bodyType);
        }
        return new PKIBody(bodyType + 1, new CertRepMessage(caPubs, response));
    }

    /**
     * Builds a {@code pollRep} body (RFC 4210 §5.2.6) signalling that the requested operation
     * is pending asynchronous completion. The CMP client should retry the poll request after
     * {@code checkAfterSeconds}.
     *
     * @param certReqId        the certificate-request ID echoed back to the client
     * @param checkAfterSeconds polling interval the client should wait before re-polling
     * @param reason           free-text reason (RFC 4210 allows informative text; may be null)
     * @return a CMP {@code pollRep} body
     */
    public static PKIBody createPollRepBody(ASN1Integer certReqId,
                                            long checkAfterSeconds,
                                            String reason) {
        PollRepContent pollRep = new PollRepContent(
                certReqId,
                new ASN1Integer(checkAfterSeconds),
                reason == null ? null : new PKIFreeText(reason));
        return new PKIBody(PKIBody.TYPE_POLL_REP, pollRep);
    }
}
