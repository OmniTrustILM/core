package com.czertainly.core.service.cmp.message.handler;

import com.czertainly.api.exception.NotFoundException;
import com.czertainly.api.interfaces.core.cmp.error.CmpCrmfValidationException;
import com.czertainly.api.model.core.certificate.CertificateDetailDto;
import com.czertainly.api.model.core.certificate.CertificateState;
import com.czertainly.api.model.core.certificate.CertificateValidationStatus;
import com.czertainly.api.model.core.cmp.CmpTransactionState;
import com.czertainly.api.model.core.v2.ClientCertificateDataResponseDto;
import com.czertainly.api.interfaces.core.cmp.error.CmpBaseException;
import com.czertainly.api.interfaces.core.cmp.error.CmpProcessingException;
import com.czertainly.core.dao.entity.Certificate;
import com.czertainly.core.dao.entity.CertificateContent;
import com.czertainly.core.dao.entity.cmp.CmpTransaction;
import com.czertainly.core.service.CertificateService;
import com.czertainly.core.service.cmp.configurations.ConfigurationContext;
import com.czertainly.core.service.cmp.message.CmpTransactionService;
import com.czertainly.core.service.cmp.message.PkiMessageDumper;
import com.czertainly.core.service.cmp.message.builder.PkiMessageBuilder;
import com.czertainly.core.service.cmp.message.validator.impl.POPValidator;
import com.czertainly.core.util.CertificateUtil;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.cmp.*;
import org.bouncycastle.asn1.crmf.CertReqMessages;
import org.bouncycastle.asn1.crmf.CertReqMsg;
import org.bouncycastle.asn1.crmf.CertRequest;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Transactional;

import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.*;

/**
 * Handle (czertainly) supported CRMF-based message - ir/cr/kur; concrete handle (how to get/update certificate)
 * delegates to another specific handlers, e.g. {@link CrmfIrCrMessageHandler} or {@link CrmfKurMessageHandler}.
 *
 * @see CrmfIrCrMessageHandler
 * @see CrmfKurMessageHandler
 */
@Component
@Transactional//(propagation = Propagation.REQUIRES_NEW)
public class CrmfMessageHandler implements MessageHandler<PKIMessage> {

    private static final Logger LOG = LoggerFactory.getLogger(CrmfMessageHandler.class.getName());

    /**
     * RFC 4210 §5.3.22 {@code checkAfter} (seconds). Tells the CMP client how long to wait
     * before retrying the {@code pollReq} when the authority provider connector accepted the
     * operation asynchronously. 60 s balances "client doesn't hammer the server" against
     * "operator doesn't wait too long for state to propagate".
     */
    private static final long POLL_REP_CHECK_AFTER_SECONDS = 60L;

    private static final List<Integer> ALLOWED_TYPES = List.of(
            PKIBody.TYPE_INIT_REQ,          // ir       [0]  CertReqMessages,       --Initialization Req
            PKIBody.TYPE_CERT_REQ,          // cr       [2]  CertReqMessages,       --Certification Req
            PKIBody.TYPE_KEY_UPDATE_REQ,    // kur      [7]  CertReqMessages,       --Key Update Request
            PKIBody.TYPE_KEY_RECOVERY_REQ,  // krr      [9]  CertReqMessages,       --Key Recovery Req     (not implemented)
            PKIBody.TYPE_CROSS_CERT_REQ);   // ccr      [13] CertReqMessages,       --Cross-Cert.  Request (not implemented)

    private CertificateService certificateService;

    @Autowired
    public void setCertificateService(CertificateService certificateService) {
        this.certificateService = certificateService;
    }

    private PollFeature pollFeature;

    @Autowired
    public void setPollFeature(PollFeature pollFeature) {
        this.pollFeature = pollFeature;
    }

    private CmpTransactionService cmpTransactionService;

    @Autowired
    public void setCmpTransactionService(CmpTransactionService cmpTransactionService) {
        this.cmpTransactionService = cmpTransactionService;
    }

    private CrmfIrCrMessageHandler crmfIrCrMessageHandler;

    @Autowired
    public void setCrmfIrCrMessageHandler(CrmfIrCrMessageHandler crmfIrCrMessageHandler) {
        this.crmfIrCrMessageHandler = crmfIrCrMessageHandler;
    }

    private CrmfKurMessageHandler kurMessageHandler;

    @Autowired
    public void setKurMessageHandler(CrmfKurMessageHandler crmfKurMessageHandler) {
        this.kurMessageHandler = crmfKurMessageHandler;
    }

    /**
     * <pre>
     * CertRequest ::= SEQUENCE {
     *      certReqId     INTEGER,        -- ID for matching request and reply
     *      certTemplate  CertTemplate, --Selected fields of cert to be issued
     * 	    controls      Controls OPTIONAL
     * } -- Attributes affecting issuance
     *
     * CertTemplate ::= SEQUENCE {
     *      version      [0] Version               OPTIONAL,
     * 		    version MUST be 2 if supplied. It SHOULD be omitted.
     * 	    serialNumber [1] INTEGER               OPTIONAL,
     * 		    serialNumber MUST be omitted. This field is assigned by the CA during certificate creation.
     * 		signingAlg   [2] AlgorithmIdentifier   OPTIONAL,
     * 		    signingAlg MUST be omitted. This field is assigned by the CA during certificate creation.
     * 		issuer       [3] Name                  OPTIONAL,
     * 		    issuer is normally omitted.  It would be filled in with the CA that the requester
     * 		    desires to issue the certificate in situations where an RA is servicing more than one CA.
     * 		validity     [4] OptionalValidity      OPTIONAL,
     *          validity is normally omitted.  It can be used to request that
     * 		    certificates either start at some point in the future or expire at
     * 		    some specific time.  A case where this field would commonly be
     * 		    used is when a cross certificate is issued for a CA.  In this case
     * 			the validity of an existing certificate would be placed in this
     * 			field so that the new certificate would have the same validity
     * 			period as the existing certificate.  If validity is not omitted,
     * 			then at least one of the sub-fields MUST be specified.
     * 		subject      [5] Name                  OPTIONAL,
     * 		    subject is filled in with the suggested name for the requester.
     * 			This would normally be filled in by a name that has been
     * 			previously issued to the requester by the CA.
     * 		publicKey    [6] SubjectPublicKeyInfo  OPTIONAL,
     * 		issuerUID    [7] UniqueIdentifier      OPTIONAL,
     * 		subjectUID   [8] UniqueIdentifier      OPTIONAL,
     * 		extensions   [9] Extensions            OPTIONAL
     * }
     *
     * 			OptionalValidity ::= SEQUENCE {
     * 			  notBefore  [0] Time OPTIONAL,
     * 			  notAfter   [1] Time OPTIONAL } --at least one must be present
     *
     * 			Time ::= CHOICE {
     * 			  utcTime        UTCTime,
     * 			  generalTime    GeneralizedTime }
     * </pre>
     *
     * @param request crmf-base message as ir, cr, kur, krr, ccr
     * @return response message related <code>request</code> message
     * @see <a href="https://www.rfc-editor.org/rfc/rfc4211#section-5">...</a>
     */
    @Override
    public PKIMessage handle(PKIMessage request, ConfigurationContext configuration) throws CmpBaseException {
        ASN1OctetString tid = request.getHeader().getTransactionID();
        int bodyType = request.getBody().getType();
        String msgBodyType = PkiMessageDumper.msgTypeAsString(request);
        if (!ALLOWED_TYPES.contains(bodyType)) {
            throw new CmpProcessingException(tid, PKIFailureInfo.systemFailure,
                    "CRMF message cannot be handled - wrong type, type=" + msgBodyType);
        }

        new POPValidator()
                .validate(request, configuration);

        CertReqMessages certReqMessages = (CertReqMessages) request.getBody().getContent();
        CertReqMsg[] certRequests = certReqMessages.toCertReqMsgArray();

        List<CertResponse> listOfCertResponses = new ArrayList<>();
        // -- czertainly is (right now) able to handle only (first) one, see {@link CrmfCertificateRequest}
        //for(var certRequest : certRequests) {

        List<CmpTransaction> trx = cmpTransactionService.findByTransactionId(tid.toString());
        if (!trx.isEmpty()) {
            throw new CmpCrmfValidationException(tid, request.getBody().getType(), PKIFailureInfo.transactionIdInUse,
                    "crmf processing failed - given transaction is already used");
        }

        CertRequest crmf = certRequests[0].getCertReq();
        ASN1Integer serialNumber = crmf.getCertTemplate().getSerialNumber();

        ClientCertificateDataResponseDto requestedCert = switch (request.getBody().getType()) {
            case PKIBody.TYPE_INIT_REQ, PKIBody.TYPE_CERT_REQ -> crmfIrCrMessageHandler.handle(request, configuration);
            case PKIBody.TYPE_KEY_UPDATE_REQ -> kurMessageHandler.handle(request, configuration);
            default -> throw new CmpProcessingException(tid, PKIFailureInfo.badRequest,
                    "CRMF message cannot be handled - type is not supported, type=" + msgBodyType);
        };
        if (requestedCert == null) {
            throw new CmpCrmfValidationException(tid, bodyType, PKIFailureInfo.badDataFormat,
                    "certificate was not provided");
        }
        // -- polling against the database
        PollResult pollResult;
        try {
            pollResult = pollFeature.pollCertificate(tid,
                    serialNumber == null ? null : serialNumber.getValue().toString(16), requestedCert.getUuid(),
                    CertificateState.ISSUED);
        } catch (CmpProcessingException e) {
            throw new CmpCrmfValidationException(tid, bodyType, e.getFailureInfo(),
                    e.getMessage());
        }

        if (pollResult instanceof PollResult.StillPending) {
            return handleAsynchronousAcceptance(tid, request, configuration, msgBodyType, requestedCert, crmf);
        }
        if (pollResult instanceof PollResult.Diverted(CertificateState currentState)) {
            throw new CmpCrmfValidationException(tid, bodyType, PKIFailureInfo.systemFailure,
                    "certificate diverted to " + currentState
                            + " while waiting for ISSUED — operation no longer in progress");
        }
        Certificate polledCert = ((PollResult.Reached) pollResult).certificate();

        // -- parse polled certificate (as X509)
        X509Certificate parsedCert = parseCertificate(tid, bodyType, polledCert);
        // -- field: caPubs
        List<CMPCertificate> listOfCaCerts = createListCaPubs(tid, bodyType, polledCert);

        // -- store as transaction (tid+uuid of cert)
        CmpTransactionState trxState = transactionStateForRequestBodyType(tid, msgBodyType, request.getBody().getType());
        cmpTransactionService.save(cmpTransactionService.createTransactionEntity(
                tid.toString(),
                configuration.getCmpProfile(),
                polledCert.getUuid().toString(),
                trxState,
                request.getBody().getType()));

        // -- create cert response
        try {
            CMPCertificate cmpCertificate = CMPCertificate.getInstance(parsedCert.getEncoded());
            listOfCertResponses.add(new CertResponse(
                    crmf.getCertReqId(),
                    new PKIStatusInfo(PKIStatus.granted),
                    new CertifiedKeyPair(new CertOrEncCert(cmpCertificate)),
                    null));
        } catch (CertificateEncodingException e) {
            LOG.error(String.format("SN=%s | CRMF cmp certificate encoding error", parsedCert.getSerialNumber()), e);
            throw new CmpCrmfValidationException(tid, request.getBody().getType(), PKIFailureInfo.badRequest,
                    "SN=" + parsedCert.getSerialNumber() + " | CRMF cmp certificate encoding error");
        }
        //}

        // -- field 'caPubs'
        CMPCertificate[] caPubs = null;
        if (!listOfCaCerts.isEmpty()) {
            caPubs = new CMPCertificate[listOfCaCerts.size()];
            listOfCaCerts.toArray(caPubs);
        }
        // -- field 'certResMessages'
        CertResponse[] certResponses = new CertResponse[listOfCertResponses.size()];
        listOfCertResponses.toArray(certResponses);

        // -- create response
        try {
            return new PkiMessageBuilder(configuration)
                    .addHeader(PkiMessageBuilder.buildBasicHeaderTemplate(request))
                    .addBody(PkiMessageBuilder.createIpCpKupBody(
                            request.getBody(),
                            certResponses,
                            caPubs))
                    .addExtraCerts(null)
                    .build();
        } catch (Exception e) {
            LOG.error("CRMF message cannot be handled", e);
            throw new CmpCrmfValidationException(tid, request.getBody().getType(), PKIFailureInfo.badDataFormat,
                    "CRMF message cannot be build, type=" + PkiMessageDumper.msgTypeAsString(request.getBody().getType()));
        }
    }

    /**
     * Connector accepted the operation asynchronously (HTTP 202): persist the transaction
     * so a subsequent {@code pollReq} can be correlated back to the in-flight cert, then
     * emit a CMP {@code pollRep} so the client knows to retry later (RFC 4210 §5.2.6).
     */
    private PKIMessage handleAsynchronousAcceptance(ASN1OctetString tid, PKIMessage request,
                                                    ConfigurationContext configuration, String msgBodyType,
                                                    ClientCertificateDataResponseDto requestedCert, CertRequest crmf) throws CmpBaseException {
        CmpTransactionState trxState = transactionStateForRequestBodyType(tid, msgBodyType, request.getBody().getType());
        cmpTransactionService.save(cmpTransactionService.createTransactionEntity(
                tid.toString(),
                configuration.getCmpProfile(),
                requestedCert.getUuid(),
                trxState,
                request.getBody().getType()));
        try {
            LOG.info("TID={} | CRMF {} accepted asynchronously (cert {}); returning pollRep",
                    tid, msgBodyType, requestedCert.getUuid());
            return new PkiMessageBuilder(configuration)
                    .addHeader(PkiMessageBuilder.buildBasicHeaderTemplate(request))
                    .addBody(PkiMessageBuilder.createPollRepBody(
                            crmf.getCertReqId(),
                            POLL_REP_CHECK_AFTER_SECONDS,
                            "Awaiting asynchronous completion"))
                    .addExtraCerts(null)
                    .build();
        } catch (Exception e) {
            LOG.error("TID={} | CRMF pollRep message cannot be built (type={})", tid, msgBodyType, e);
            throw new CmpCrmfValidationException(tid, request.getBody().getType(), PKIFailureInfo.systemFailure,
                    "CRMF pollRep cannot be built, type=" + PkiMessageDumper.msgTypeAsString(request.getBody().getType()));
        }
    }

    private CmpTransactionState transactionStateForRequestBodyType(ASN1OctetString tid, String msgBodyType, int requestBodyType)
            throws CmpProcessingException {
        return switch (requestBodyType) {
            case PKIBody.TYPE_INIT_REQ, PKIBody.TYPE_CERT_REQ -> crmfIrCrMessageHandler.getTransactionState();
            case PKIBody.TYPE_KEY_UPDATE_REQ -> kurMessageHandler.getTransactionState();
            default -> throw new CmpProcessingException(tid, PKIFailureInfo.badRequest,
                    "CRMF message cannot be handled - type is not supported, type=" + msgBodyType);
        };
    }

    /**
     * <p>Parse given certificate (as {@link Certificate}) to {@link X509Certificate}.</p>
     *
     * @param tid        transactionID of given flow (request/response)
     * @param bodyType   type of given message (ir, cr, kur, krr, ccr)
     * @param polledCert which is parsed
     * @return parsed (entity) certificate into certificate in x509 format
     * @throws CmpCrmfValidationException if any problem is raised
     */
    private X509Certificate parseCertificate(ASN1OctetString tid, int bodyType, Certificate polledCert)
            throws CmpCrmfValidationException {
        if (polledCert == null) {
            throw new CmpCrmfValidationException(tid, bodyType, PKIFailureInfo.badDataFormat,
                    "unable to parse empty certificate");
        }
        String serialNumber = polledCert.getSerialNumber();
        CertificateContent polledCertContent = polledCert.getCertificateContent();
        if (polledCertContent == null || polledCertContent.getContent().isEmpty()) {
            throw new CmpCrmfValidationException(tid, bodyType, PKIFailureInfo.badDataFormat,
                    "SN=" + serialNumber + " | unable to parse empty certificate content");
        }

        try {
            return CertificateUtil.parseCertificate(polledCertContent.getContent());
        } catch (CertificateException e) {
            LOG.error(String.format("SN=%s | unable to parse given certificate content", serialNumber), e);
            throw new CmpCrmfValidationException(tid, bodyType, PKIFailureInfo.badDataFormat,
                    "SN=" + serialNumber + " | unable to parse given certificate content");
        }
    }

    /**
     * <p>See Section 5.3.4 for CertRepMessage syntax.  Note that if the PKI
     * Message Protection is "shared secret information" (see Section
     * 5.1.3), then any certificate transported in the caPubs field may be
     * directly trusted as a root CA certificate by the initiator.</p>
     * <p>Scope: ip, cp, kup, ccp</p>
     * <p>Location: (optional) CertRepMessage.caPubs</p>
     *
     * <pre>
     *     new CMPCertificate[2];
     *             caPubs[1] = CMPCertificate.getInstance(CA_ROOT_CERT.getEncoded());
     *             caPubs[0] = CMPCertificate.getInstance(CA_INTERMEDIATE_CERT.getEncoded());
     * </pre>
     *
     * @param tid,            transactionID of given flow (request/response)
     * @param leafCertificate which is ca chain built from
     * @return null, if ca chain is empty
     * @see <a href="https://www.rfc-editor.org/rfc/rfc4210#section-5.3.2">...</a>
     */
    private List<CMPCertificate> createListCaPubs(ASN1OctetString tid, int bodyType, Certificate leafCertificate)
            throws CmpProcessingException {
        try {
            List<X509Certificate> caChain = loadCaCertificateChain(tid, bodyType, leafCertificate);
            List<CMPCertificate> converted = new LinkedList<>();
            for (X509Certificate cr : caChain) {
                converted.add(CertificateUtil.toCmpCertificate(cr));
            }
            return converted;
        } catch (CertificateException e) {
            LOG.error(String.format("SN=%s | problem with convert of CA: from (x509) certificates to (cmp) certificates", leafCertificate.getSerialNumber()), e);
            throw new CmpCrmfValidationException(tid, bodyType, PKIFailureInfo.systemFailure,
                    String.format("SN=%s | problem with convert of CA: from (x509) certificates to (cmp) certificates", leafCertificate.getSerialNumber()));
        }
    }

    private List<X509Certificate> loadCaCertificateChain(ASN1OctetString tid, int bodyType, Certificate leafCertificate)
            throws CmpProcessingException {
        ArrayList<X509Certificate> certificateChain = new ArrayList<>();

        // -- try to find CA chain from leaf certificate (can be null/empty==not found)
        List<CertificateDetailDto> caChain;
        String leafCertificateSerialNumber = leafCertificate.getSerialNumber();
        try {
            caChain = certificateService.getCertificateChain(
                    leafCertificate.getSecuredUuid(), true).getCertificates();
        } catch (NotFoundException e) {
            LOG.error("TID={}, SN={} | CA chain is empty (not found)", tid, leafCertificateSerialNumber);
            return certificateChain;
        }

        // -- parse found CA certificate(s)
        for (CertificateDetailDto certificate : caChain) {
            // only certificate with valid status should be used
            if (certificate.getValidationStatus() != CertificateValidationStatus.VALID
                    && certificate.getValidationStatus() != CertificateValidationStatus.EXPIRING) {
                throw new CmpCrmfValidationException(tid, bodyType, PKIFailureInfo.systemFailure,
                        String.format("SN=%s | Certificate is not valid. UUID: %s, Fingerprint: %s, Status: %s",
                                leafCertificateSerialNumber,
                                certificate.getUuid(),
                                certificate.getFingerprint(),
                                certificate.getValidationStatus().getLabel()));
            }
            try {
                certificateChain.add(CertificateUtil.parseCertificate(certificate.getCertificateContent()));
            } catch (CertificateException e) { // This should not happen
                throw new CmpCrmfValidationException(tid, bodyType, PKIFailureInfo.systemFailure,
                        String.format("SN=%s | Failed to parse certificate (caSN=%s); content=%s",
                                leafCertificateSerialNumber,
                                certificate.getSerialNumber(),
                                certificate.getCertificateContent()));
            }
        }
        return certificateChain;
    }

}
