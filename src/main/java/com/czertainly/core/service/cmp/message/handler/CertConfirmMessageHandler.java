package com.czertainly.core.service.cmp.message.handler;

import com.czertainly.api.interfaces.core.cmp.error.CmpBaseException;
import com.czertainly.api.interfaces.core.cmp.error.CmpProcessingException;
import com.czertainly.api.interfaces.core.cmp.error.ImplFailureInfo;
import com.czertainly.api.model.core.cmp.CmpTransactionState;
import com.czertainly.core.dao.entity.Certificate;
import com.czertainly.core.dao.entity.cmp.CmpTransaction;
import com.czertainly.core.service.cmp.configurations.ConfigurationContext;
import com.czertainly.core.service.cmp.message.CmpTransactionService;
import com.czertainly.core.service.cmp.message.PkiMessageDumper;
import com.czertainly.core.service.cmp.message.builder.PkiMessageBuilder;
import com.czertainly.core.util.CertificateUtil;
import com.czertainly.core.util.CryptographyUtil;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.cmp.*;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.operator.DefaultDigestAlgorithmIdentifierFinder;
import org.bouncycastle.operator.DigestAlgorithmIdentifierFinder;
import org.bouncycastle.operator.DigestCalculator;
import org.bouncycastle.operator.bc.BcDigestCalculatorProvider;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Transactional;

import java.security.cert.X509Certificate;
import java.util.List;

/**
 * Handler for certification confirmation message.
 * <pre>
 *   type:
 *      {@link PKIBody#TYPE_CERT_CONFIRM}
 *   content:
 *      certConf [24] CertConfirmContent,    --Certificate confirm
 * </pre>
 */
@Component
@Transactional
public class CertConfirmMessageHandler implements MessageHandler<PKIMessage> {

    private static final Logger LOG = LoggerFactory.getLogger(CertConfirmMessageHandler.class.getName());

    private CmpTransactionService cmpTransactionService;

    @Autowired
    public void setCmpTransactionService(CmpTransactionService cmpTransactionService) {
        this.cmpTransactionService = cmpTransactionService;
    }

    /**
     * <pre>
     *    Certificate confirm; certConf
     *
     *    Field                Value
     *    sender               present
     *      -- same as in ir
     *
     *    recipient            CA name
     *      -- the name of the CA who was asked to produce a certificate
     *
     *    transactionID        present
     *      -- value from corresponding ir and ip messages
     *
     *    senderNonce          present
     *      -- 128 (pseudo-) random bits
     *
     *    recipNonce           present
     *      -- value from senderNonce in corresponding ip message
     *
     *    protectionAlg        MSG_MAC_ALG
     *      -- only MAC protection is allowed for this message.  The
     *      -- MAC is based on the initial authentication key shared
     *      -- between the EE and the CA.
     *
     *    senderKID            referenceNum
     *      -- the reference number which the CA has previously issued
     *      -- to the end entity (together with the MAC-ing key)
     *
     *    body                 certConf
     *      -- see Section 5.3.18, "PKI Confirmation Content", for the
     *      -- contents of the certConf fields.
     *      -- Note: two CertStatus structures are required if both an
     *      -- encryption and a signing certificate were sent.
     *
     *    protection           present
     *      -- bits calculated using MSG_MAC_ALG
     * </pre>
     * <pre>
     *     CertConfirmContent ::= SEQUENCE OF CertStatus
     *          CertStatus ::= SEQUENCE {
     *             certHash    OCTET STRING,
     *             certReqId   INTEGER,
     *             statusInfo  PKIStatusInfo OPTIONAL
     *          }
     * </pre>
     *
     * @see <a href="https://www.rfc-editor.org/rfc/rfc4210#section-5.3.18">Certificate Confirmation Content</a>
     */
    @Override
    public PKIMessage handle(PKIMessage request, ConfigurationContext configuration) throws CmpBaseException {
        ASN1OctetString tid = request.getHeader().getTransactionID();
        String msgBodyAsString = PkiMessageDumper.msgTypeAsString(request.getBody().getType());
        if (PKIBody.TYPE_CERT_CONFIRM != request.getBody().getType()) {
            throw new CmpProcessingException(tid, PKIFailureInfo.systemFailure,
                    "confirmation (certConf) message cannot be handled - " +
                            "unsupported body rawType=" + request.getBody().getType() +
                            ", type=" + msgBodyAsString +
                            "; only type=cerfConf is supported");
        }

        CertConfirmContent certConfirmBody = (CertConfirmContent) request.getBody().getContent();
        CertStatus[] certStatuses = certConfirmBody.toCertStatusArray();
        for (var certStatus : certStatuses) {
            processConfirmation(tid, certStatus);
        }

        try {
            return new PkiMessageBuilder(configuration)
                    .addHeader(PkiMessageBuilder.buildBasicHeaderTemplate(request))
                    .addBody(new PKIBody(PKIBody.TYPE_CONFIRM, new PKIConfirmContent()))
                    .addExtraCerts(null)
                    .build();
        } catch (Exception e) {
            throw new CmpProcessingException(tid, PKIFailureInfo.badDataFormat,
                    "problem build pkiConfirm response message, type=" + msgBodyAsString, e);
        }
    }

    private void processConfirmation(ASN1OctetString tid, CertStatus certStatus)
            throws CmpProcessingException {
        ASN1OctetString incomingFingerprint = certStatus.getCertHash();
        //flag if certificate has been found and confirmed
        boolean confirmed = false;

        // find related transactions by transactionId
        // (note: many certificates can be related to one transactionId - future use case; actually 1 trx == 1 cert)
        List<CmpTransaction> relatedTransactions = cmpTransactionService.findByTransactionId(tid.toString());

        // check the fingerprint with the certificate stored in transaction
        for (CmpTransaction cmpTransaction : relatedTransactions) {
            ASN1OctetString fingerprint = getFingerprint(tid, cmpTransaction.getCertificate());
            LOG.debug("TID={}, FP={}, CFP={} | compare fingerprints", tid, incomingFingerprint, fingerprint);
            if (fingerprint.equals(incomingFingerprint)) {
                cmpTransaction.setState(CmpTransactionState.CERT_CONFIRMED);
                cmpTransactionService.save(cmpTransaction);
                confirmed = true;
            }
        }

        if (!confirmed) {
            LOG.warn("TID={}, FP={} | certConf fingerprint does not match any certificate in this transaction",
                    tid, incomingFingerprint);
            throw new CmpProcessingException(tid, PKIFailureInfo.badCertId,
                    ImplFailureInfo.CMPHANCERTCONF002);
        }
    }

    private static final DigestAlgorithmIdentifierFinder DIGEST_ALG_FINDER = new DefaultDigestAlgorithmIdentifierFinder();
    private static final BcDigestCalculatorProvider DIGEST_CALCULATOR_PROVIDER = new BcDigestCalculatorProvider();

    private ASN1OctetString getFingerprint(ASN1OctetString tid, Certificate certificate) throws CmpProcessingException {
        try {
            X509Certificate x509Cert = CertificateUtil.parseCertificate(certificate.getCertificateContent().getContent());
            AlgorithmIdentifier sigAlgId = CryptographyUtil.getAlgorithmIdentifierInstance(x509Cert.getSigAlgName());
            LOG.debug("TID={} | certificate signature algorithm: {}", tid, sigAlgId.getAlgorithm().getId());
            DigestCalculator digester = DIGEST_CALCULATOR_PROVIDER.get(DIGEST_ALG_FINDER.find(sigAlgId));
            LOG.debug("TID={} | certificate fingerprint algorithm: {}", tid, digester.getAlgorithmIdentifier().getAlgorithm().getId());
            digester.getOutputStream().write(x509Cert.getEncoded());
            return new DEROctetString(digester.getDigest());
        } catch (Exception e) {
            LOG.error("TID={} | failed to compute certificate fingerprint", tid, e);
            throw new CmpProcessingException(tid, PKIFailureInfo.badMessageCheck,
                    "problem to compute certificate fingerprint (cert hash): " + e.getMessage(), e);
        }
    }
}
