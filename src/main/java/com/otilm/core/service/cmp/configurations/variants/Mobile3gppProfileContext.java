package com.otilm.core.service.cmp.configurations.variants;

import com.otilm.api.model.client.attribute.RequestAttribute;
import com.otilm.api.interfaces.core.cmp.error.CmpCrmfValidationException;
import com.otilm.api.interfaces.core.cmp.error.CmpProcessingException;
import com.otilm.core.dao.entity.RaProfile;
import com.otilm.core.service.cmp.message.CertificateKeyService;
import com.otilm.core.dao.entity.cmp.CmpProfile;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.cmp.*;
import org.bouncycastle.asn1.crmf.CertReqMessages;
import org.bouncycastle.asn1.crmf.CertReqMsg;
import org.bouncycastle.asn1.crmf.CertTemplate;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;

import java.util.List;

/**
 * Implementation/variation of CMP protocol for 3GPP standard
 */
public class Mobile3gppProfileContext extends CmpConfigurationContext {

    public Mobile3gppProfileContext(CmpProfile cmpProfile, RaProfile raProfile, PKIMessage pkiRequest,
                                    CertificateKeyService certificateKeyServiceImpl,
                                    List<RequestAttribute> issueAttributes,
                                    List<RequestAttribute> revokeAttributes) {
        super(cmpProfile, raProfile, pkiRequest, certificateKeyServiceImpl, issueAttributes, revokeAttributes);
    }

    /**
     * <p>The subject field of the CertTemplate shall contain the suggested name of the base
     * station if the base station has knowledge of it. Otherwise it shall be omitted.</p>
     *
     * <p>The publicKey field of the CertTemplate shall be mandatory and shall contain the public
     * key of the base station to be certified by the RA/CA. The private/public key pair may be
     * pre-provisioned to the base station, or generated inside the base station for the CMPv2
     * protocol run. The format of this field shall follow IETF RFC 5280 [14].
     * <p>
     * source: 9.5.4.2	Initialization Request
     * </p>
     */
    @Override
    public void validateOnCrmfRequest(PKIMessage request) throws CmpProcessingException {
        ASN1OctetString tid = request.getHeader().getTransactionID();
        int bodyType = request.getBody().getType();
        switch (bodyType) {
            case PKIBody.TYPE_INIT_REQ:
                CertReqMessages content = (CertReqMessages) request.getBody().getContent();
                CertReqMsg[] certReqMsgs = content.toCertReqMsgArray();
                // All CMPv2 messages used within this profile shall consist of exactly one
                // PKIMessage, i.e. the size of the sequence for PKIMessages shall be 1 in
                // all cases.
                // see 9.5.2	Profile for the PKIMessage
                if (certReqMsgs.length > 1) {
                    throw new CmpCrmfValidationException(tid, bodyType,
                            PKIFailureInfo.badDataFormat, "only one certReqMsg is allowed");
                }
                /*
                 * <p>The publicKey field of the CertTemplate shall be mandatory and shall contain
                 * the public key of the base station to be certified by the RA/CA.
                 * The private/public key pair may be pre-provisioned to the base station,
                 * or generated inside the base station for the CMPv2 protocol run.
                 * </p>
                 *
                 * @param certReqMsgs which keeps related certificate
                 * @return public key wrapper
                 *
                 * @see 9.5.4.2	Initialization Request (chapter 9 Base Station), 3gpp 310
                 */
                CertTemplate certTemplate = certReqMsgs[0].getCertReq().getCertTemplate();
                SubjectPublicKeyInfo publicKey = certTemplate.getPublicKey();
                if (publicKey == null) {
                    throw new CmpCrmfValidationException(tid, bodyType,
                            PKIFailureInfo.badCertTemplate, "public key in template is null");
                }
            case PKIBody.TYPE_CERT_REQ:
            case PKIBody.TYPE_KEY_UPDATE_REQ:
                break;// do something
            default:
                throw new CmpProcessingException(tid,
                        PKIFailureInfo.badDataFormat, "only CRMF-based message can be validated");
        }
    }

    /**
     * <p>(3gpp) validation of crmf based response messages</p>
     *
     * <p>
     * The support of the optional extraCerts field is required by this profile. The certificates within
     * this field may be ordered in any order. The message-specific content of this field is specified
     * in the subclause   9.5.4 in the profiling of the single PKI message bodies.
     * </p>
     * <p>
     * (3gpp) 9.5.4.3	Initialization Response</p>
     *
     * <p>
     * The extraCerts field of the PKIMessage carrying the initialization response shall be mandatory and shall
     * contain the operator root certificate and the RA/CA certificate (or certificates if separate private keys
     * are used for signing of certificates and CMP messages). If the RA/CA certificate(s) are not signed by the
     * operator root CA, also the intermediate certificates for the chain(s) up to the operator root certificate
     * shall be included in the extraCerts field. If additional (self-signed) Root CA certificates are required,
     * they shall be carried in the extraCerts field or caPubs field of the PKIMessage. Since extraCerts field is
     * not under CMP message integrity protection, CMP over TLS should be used as a security transport mechanism.
     * Since CMP already supports integrity protection for caPubs field, the use of security transport mechanisms
     * is optional.</p>
     */
    @Override
    public void validateOnCrmfResponse(PKIMessage response) throws CmpProcessingException {
        ASN1OctetString tid = response.getHeader().getTransactionID();
        int bodyType = response.getBody().getType();
        switch (bodyType) {
            case PKIBody.TYPE_INIT_REP:
            case PKIBody.TYPE_CERT_REP:
            case PKIBody.TYPE_KEY_UPDATE_REP:
                // The extraCerts requirement only applies to a response that actually carries
                // an issued certificate. A pending response (RFC 4210 §5.3.22 PKIStatus
                // 'waiting', emitted while issuance completes asynchronously) has no
                // certifiedKeyPair and therefore no chain to advertise — exempt it.
                if (carriesIssuedCertificate(response)
                        && (response.getExtraCerts() == null || response.getExtraCerts().length == 0)) {
                    throw new CmpCrmfValidationException(tid, bodyType,
                            PKIFailureInfo.badDataFormat, "field 'extraCerts' is null or empty");
                }
                break;// do something
            default:
                throw new CmpProcessingException(tid,
                        PKIFailureInfo.badDataFormat, "only CRMF-based message can be validated");
        }
    }

    /**
     * A CRMF response carries an issued certificate when its first {@link CertResponse} has a
     * {@link CertifiedKeyPair}. A pending ({@code waiting}) response has none, so the
     * extraCerts chain requirement does not apply to it.
     */
    private static boolean carriesIssuedCertificate(PKIMessage response) {
        if (!(response.getBody().getContent() instanceof CertRepMessage certRepMessage)) {
            return false;
        }
        CertResponse[] responses = certRepMessage.getResponse();
        return responses != null && responses.length > 0
                && responses[0].getCertifiedKeyPair() != null;
    }

}
