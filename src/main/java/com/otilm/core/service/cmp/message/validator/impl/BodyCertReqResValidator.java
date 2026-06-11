package com.otilm.core.service.cmp.message.validator.impl;

import com.otilm.api.interfaces.core.cmp.error.CmpProcessingException;
import com.otilm.api.interfaces.core.cmp.error.CmpCrmfValidationException;
import com.otilm.core.service.cmp.configurations.ConfigurationContext;
import com.otilm.core.service.cmp.message.PkiMessageDumper;
import com.otilm.core.service.cmp.message.validator.BiValidator;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.cmp.*;
import org.bouncycastle.asn1.crmf.CertReqMessages;
import org.bouncycastle.asn1.crmf.CertReqMsg;
import org.bouncycastle.asn1.crmf.CertRequest;
import org.bouncycastle.asn1.crmf.CertTemplate;

import java.util.Objects;

/**
 * <p>Validator for incoming message {@link CertReqMessages} and outgoing
 * message {@link CertRepMessage}.</p>
 *
 * <p>It means these {@link PKIBody#getType()}:</p>
 * <ul>
 *     <li>{@link PKIBody#TYPE_INIT_REQ}</li>
 *     <li>{@link PKIBody#TYPE_INIT_REP}</li>
 *     <li>{@link PKIBody#TYPE_CERT_REQ}</li>
 *     <li>{@link PKIBody#TYPE_CERT_REP}</li>
 *     <li>{@link PKIBody#TYPE_KEY_UPDATE_REQ}</li>
 *     <li>{@link PKIBody#TYPE_KEY_UPDATE_REP}</li>
 *     <li>{@link PKIBody#TYPE_CROSS_CERT_REQ} - <b>not implemented in ILM</b></li>
 *     <li>{@link PKIBody#TYPE_CROSS_CERT_REP} - <b>not implemented in ILM</b></li>
 * </ul>
 *
 * @see <a href="https://www.rfc-editor.org/rfc/rfc4211#section-3">CertReqMessage Syntax</a>
 * @see <a href="https://www.rfc-editor.org/rfc/rfc4210#appendix-F">Appendix F.  Compilable ASN.1 Definitions (rfc4210)</a>
 */
public class BodyCertReqResValidator extends BaseValidator implements BiValidator<Void, Void> {

    /**
     * <p>Validate ir, cr, kur (CertReqMessage) messages.</p>
     *
     * <p>CertReqMessage Syntax</p>
     * <pre>
     *    CertReqMessages ::= SEQUENCE SIZE (1..MAX) OF CertReqMsg
     *
     *    CertReqMsg ::= SEQUENCE {
     *       certReq   CertRequest,
     *       popo       ProofOfPossession  OPTIONAL,
     *       -- content depends upon key type
     *       regInfo   SEQUENCE SIZE(1..MAX) of AttributeTypeAndValue OPTIONAL
     *    }
     *
     *    CertRequest ::= SEQUENCE {
     *       certReqId     INTEGER,        -- ID for matching request and reply
     *       certTemplate  CertTemplate, --Selected fields of cert to be issued
     *       controls      Controls OPTIONAL } -- Attributes affecting issuance
     *
     *    CertTemplate ::= SEQUENCE {
     *       version      [0] Version               OPTIONAL,
     *       serialNumber [1] INTEGER               OPTIONAL,
     *       signingAlg   [2] AlgorithmIdentifier   OPTIONAL,
     *       issuer       [3] Name                  OPTIONAL,
     *       validity     [4] OptionalValidity      OPTIONAL,
     *       subject      [5] Name                  OPTIONAL,
     *       publicKey    [6] SubjectPublicKeyInfo  OPTIONAL,
     *       issuerUID    [7] UniqueIdentifier      OPTIONAL,
     *       subjectUID   [8] UniqueIdentifier      OPTIONAL,
     *       extensions   [9] Extensions            OPTIONAL }
     *
     *    OptionalValidity ::= SEQUENCE {
     *       notBefore  [0] Time OPTIONAL,
     *       notAfter   [1] Time OPTIONAL } --at least one must be present
     *
     *    Time ::= CHOICE {
     *       utcTime        UTCTime,
     *       generalTime    GeneralizedTime }
     * </pre>
     *
     * @param request correspondent type of {@link CertReqMessages} to given parameter <code>bodyType</code>
     * @throws CmpProcessingException if validation will fail
     * @see <a href="https://www.rfc-editor.org/rfc/rfc4211#section-3">CertReqMessage Syntax</a>
     * @see <a href="https://www.rfc-editor.org/rfc/rfc4210#appendix-F">Appendix F.  Compilable ASN.1 Definitions (rfc4210)</a>
     */
    @Override
    public Void validateIn(PKIMessage request, ConfigurationContext configuration) throws CmpProcessingException {
        ASN1OctetString tid = request.getHeader().getTransactionID();
        CertReqMessages content = (CertReqMessages) request.getBody().getContent();
        int bodyType = request.getBody().getType();
        CertReqMsg[] certReqMsgs = content.toCertReqMsgArray();
        if (certReqMsgs == null) {
            throw new CmpCrmfValidationException(tid, bodyType, PKIFailureInfo.addInfoNotAvailable,
                    PkiMessageDumper.msgTypeAsString(bodyType) + ": missing 'certReqMsgs'");
        }
        if (certReqMsgs.length == 0) {
            throw new CmpCrmfValidationException(tid, bodyType, PKIFailureInfo.badDataFormat,
                    PkiMessageDumper.msgTypeAsString(bodyType) + ": 'certReqMsgs' cannot be empty");
        }
        if (certReqMsgs[0] == null) {
            throw new CmpCrmfValidationException(tid, bodyType, PKIFailureInfo.addInfoNotAvailable,
                    PkiMessageDumper.msgTypeAsString(bodyType) + ": 'certReqMsgs' has no value");
        }
        // -- CertReqMsg/certReq
        CertReqMsg certReqMsg = certReqMsgs[0];
        CertRequest certReq = certReqMsg.getCertReq();
        if (!Objects.equals(certReq.getCertReqId(), ZERO)) {
            throw new CmpProcessingException(tid, PKIFailureInfo.badDataFormat,
                    PkiMessageDumper.msgTypeAsString(bodyType) + ": certReq must be zero");
        }
        // -- certTemplate/version,  version MUST be 2 if supplied.
        CertTemplate certTemplate = certReq.getCertTemplate();
        int versionInTemplate = certTemplate.getVersion();
        if (versionInTemplate != -1 && versionInTemplate != 2) {
            throw new CmpProcessingException(tid,
                    PKIFailureInfo.badCertTemplate,
                    PkiMessageDumper.msgTypeAsString(bodyType) + ": certTemplate version must be -1 or 2");
        }
        // -- certTemplate/subject
        if (Objects.isNull(certTemplate.getSubject())) {
            throw new CmpCrmfValidationException(tid, bodyType, PKIFailureInfo.badCertTemplate,
                    PkiMessageDumper.msgTypeAsString(bodyType) + ": subject in template is missing");
        }
        configuration.validateOnCrmfRequest(request);
        return null;//validation is ok
    }

    /**
     * Validate ip, cp, kup (response) message
     *
     * <pre>
     *      CertRepMessage ::= SEQUENCE {
     *          caPubs       [1] SEQUENCE SIZE (1..MAX) OF CMPCertificate
     *                           OPTIONAL,
     *          response         SEQUENCE OF CertResponse
     *      }
     *
     *      CertResponse ::= SEQUENCE {
     *          certReqId           INTEGER,
     *          -- to match this response with corresponding request (a value
     *          -- of -1 is to be used if certReqId is not specified in the
     *          -- corresponding request)
     *          status              PKIStatusInfo,
     *          certifiedKeyPair    CertifiedKeyPair    OPTIONAL,
     *          rspInfo             OCTET STRING        OPTIONAL
     *          -- analogous to the id-regInfo-utf8Pairs string defined
     *          -- for regInfo in CertReqMsg [CRMF]
     *      }
     *
     *      CertifiedKeyPair ::= SEQUENCE {
     *          certOrEncCert       CertOrEncCert,
     *          privateKey      [0] EncryptedValue      OPTIONAL,
     *          -- see [CRMF] for comment on encoding
     *          publicationInfo [1] PKIPublicationInfo  OPTIONAL
     *      }
     *
     *      CertOrEncCert ::= CHOICE {
     *          certificate     [0] CMPCertificate,
     *          encryptedCert   [1] EncryptedValue
     *      }
     * </pre>
     *
     * @param response correspondent type of {@link CertRepMessage} to given parameter <code>bodyType</code>
     * @throws CmpProcessingException if validation will fail
     */
    @Override
    public Void validateOut(PKIMessage response, ConfigurationContext configuration) throws CmpProcessingException {
        ASN1OctetString tid = response.getHeader().getTransactionID();
        CertRepMessage content = (CertRepMessage) response.getBody().getContent();
        CertResponse[] responses = content.getResponse();
        CertResponse certResponse = responses[0];
        assertEqual(tid, certResponse.getCertReqId(), ZERO, "value must be zero");
        CertifiedKeyPair certifiedKeyPair = certResponse.getCertifiedKeyPair();
        if (certifiedKeyPair != null) {
            validatePositiveStatus(tid, certResponse.getStatus());
            CertOrEncCert certOrEncCert = certifiedKeyPair.getCertOrEncCert();
            checkValueNotNull(tid, certOrEncCert, PKIFailureInfo.badDataFormat, "CertOrEncCert");
            checkValueNotNull(tid, certOrEncCert.getCertificate(), PKIFailureInfo.badDataFormat, "Certificate");
        } else {
            validateNegativeStatus(tid, certResponse.getStatus());
        }
        configuration.validateOnCrmfResponse(response);
        return null;
    }
}
