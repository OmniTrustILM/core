package com.otilm.core.service.cmp.message.validator.impl;

import com.otilm.api.interfaces.core.cmp.error.CmpBaseException;
import com.otilm.api.interfaces.core.cmp.error.CmpCrmfValidationException;
import com.otilm.api.interfaces.core.cmp.error.CmpProcessingException;
import com.otilm.api.interfaces.core.cmp.error.ImplFailureInfo;
import com.otilm.core.service.cmp.configurations.ConfigurationContext;
import com.otilm.core.service.cmp.message.validator.Validator;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.cmp.PKIBody;
import org.bouncycastle.asn1.cmp.PKIFailureInfo;
import org.bouncycastle.asn1.cmp.PKIMessage;
import org.bouncycastle.asn1.crmf.*;

/**
 * <h6>Proof-of-Possession (POP)</h6>
 * Short fields overview:
 * <pre>
 *     ProofOfPossession ::= CHOICE {
 *          raVerified        [0] NULL,
 *          signature         [1] POPOSigningKey,
 *          keyEncipherment   [2] POPOPrivKey,
 *          keyAgreement      [3] POPOPrivKey }
 *
 *      POPOSigningKey ::= SEQUENCE {
 *          poposkInput         [0] POPOSigningKeyInput OPTIONAL,
 *          algorithmIdentifier     AlgorithmIdentifier,
 *          signature               BIT STRING }
 * </pre>
 *
 * <p>POP for a signature key is accomplished by performing a signature
 * operation on a piece of data containing the identity for which the
 * certificate is desired.
 * </p>
 *
 * <p>There are three cases that need to be looked at when doing a POP for
 * a signature key:</p>
 * <ul>
 *     <li>
 * 1.  The certificate subject has not yet established an authenticated
 *     identity with a CA/RA, but has a password and identity string
 *     from the CA/RA.  In this case, the POPOSigningKeyInput structure
 *     would be filled out using the publicKeyMAC choice for authInfo,
 *     and the password and identity would be used to compute the
 *     publicKeyMAC value.  The public key for the certificate being
 *     requested would be placed in both the POPOSigningKeyInput and the
 *     Certificate Template structures.  The signature field is computed
 *     over the DER-encoded POPOSigningKeyInput structure.</li>
 *
 *        <li>
 *    2.  The CA/RA has established an authenticated identity for the
 *        certificate subject, but the requester is not placing it into the
 *        certificate request.  In this case, the POPOSigningKeyInput
 *        structure would be filled out using the sender choice for
 *        authInfo.  The public key for the certificate being requested
 *        would be placed in both the POPOSigningKeyInput and the
 *        Certificate Template structures.  The signature field is computed
 *        over the DER-encoded POPOSigningKeyInput structure.</li>
 *
 * @see <a href="https://www.ssl.com/how-to/proving-possession-of-a-private-key/">example using of POP at ssl.com</a>
 * @see <a href="https://www.rfc-editor.org/rfc/rfc4210#section-5.2.8">Proof-of-Possession Structures at rfc4210</a>
 * @see <a href="https://www.rfc-editor.org/rfc/rfc4210#section-5.2.8.4"> Summary of PoP Options at rfc4210</a>
 * @see <a href="https://www.rfc-editor.org/rfc/rfc4210#appendix-D.3">Proof of Possesion Profile at rfc4210</a>
 * @see <a href="https://www.rfc-editor.org/rfc/rfc4211#section-4">Proof-of-Possession (POP) at rfc4211</a>
 * @see <a href="https://www.rfc-editor.org/rfc/rfc4211#section-4.1">Signature Key POP at rfc4211</a>
 */
public class POPValidator implements Validator<PKIMessage, Void> {

    /**
     * Find public key (from ${@link PKIBody}/${@link CertTemplate}) and verify signature
     * (client used its private key) of ${@link CertRequest} data. Attention: only CRMF-based message
     * can use this validator (otherwise )!
     *
     * @param message which has been used for Proof-of-Possession (POP) verification
     * @return Void/null is ok
     * @throws CmpBaseException if any problem (technically or with implementation)
     * @see <a href="https://www.rfc-editor.org/rfc/rfc4211#section-3">CertReqMessages syntax</a>
     */
    @Override
    public Void validate(PKIMessage message, ConfigurationContext configuration) throws CmpBaseException {
        if (!SUPPORTED_CRMF_MESSAGES_TYPES.contains(message.getBody().getType())) {
            throw new CmpProcessingException(PKIFailureInfo.systemFailure, //system uses this validator bad way
                    "validation pop: cannot use proofOfPossession verification for given message body/type, type="
                            + message.getBody().getType());
        }
        ASN1OctetString tid = message.getHeader().getTransactionID();
        CertReqMsg certReqMsg = ((CertReqMessages) message.getBody().getContent()).toCertReqMsgArray()[0];
        ProofOfPossession proofOfPossession = certReqMsg.getPop();

        if (proofOfPossession == null) {
            throw new CmpCrmfValidationException(tid, message.getBody().getType(), PKIFailureInfo.badPOP,
                    ImplFailureInfo.CMPVALPOP504);
        }

        // -- pop type (dispatch type of validation)
        switch (proofOfPossession.getType()) {
            case ProofOfPossession.TYPE_RA_VERIFIED:
                throw new CmpCrmfValidationException(tid, message.getBody().getType(), PKIFailureInfo.badPOP,
                        ImplFailureInfo.CMPVALPOP505);
            case ProofOfPossession.TYPE_KEY_AGREEMENT:
            case ProofOfPossession.TYPE_KEY_ENCIPHERMENT:
                throw new CmpCrmfValidationException(tid, message.getBody().getType(), PKIFailureInfo.badPOP,
                        "validation pop: the given proofOfPossession type is not implemented yet");
            case ProofOfPossession.TYPE_SIGNING_KEY:
                POPOSigningKey popoSigningKey = (POPOSigningKey) proofOfPossession.getObject();
                if (popoSigningKey.getPoposkInput() == null) {
                    /*
                     *    3.  The certificate subject places its name in the Certificate
                     *        Template structure along with the public key.  In this case the
                     *        poposkInput field is omitted from the POPOSigningKey structure.
                     *        The signature field is computed over the DER-encoded certificate
                     *        template structure.
                     *
                     * see https://www.rfc-editor.org/rfc/rfc4211#section-4.1, point 3
                     */
                    new POPSigningKeyCertTemplateValidator().validate(message, configuration);
                    break;
                } else {
                    /*
                     *    1.  The certificate subject has not yet established an authenticated
                     *        identity with a CA/RA, but has a password and identity string
                     *        from the CA/RA.  In this case, the POPOSigningKeyInput structure
                     *        would be filled out using the publicKeyMAC choice for authInfo,
                     *        and the password and identity would be used to compute the
                     *        publicKeyMAC value.  The public key for the certificate being
                     *        requested would be placed in both the POPOSigningKeyInput and the
                     *        Certificate Template structures.  The signature field is computed
                     *        over the DER-encoded POPOSigningKeyInput structure.
                     *
                     *    2.  The CA/RA has established an authenticated identity for the
                     *        certificate subject, but the requester is not placing it into the
                     *        certificate request.  In this case, the POPOSigningKeyInput
                     *        structure would be filled out using the sender choice for
                     *        authInfo.  The public key for the certificate being requested
                     *        would be placed in both the POPOSigningKeyInput and the
                     *        Certificate Template structures.  The signature field is computed
                     *        over the DER-encoded POPOSigningKeyInput structure.
                     */
                    throw new CmpCrmfValidationException(tid, message.getBody().getType(), PKIFailureInfo.badPOP,
                            ImplFailureInfo.CMPVALPOP508);
                }
            default:
                throw new CmpCrmfValidationException(tid, message.getBody().getType(), PKIFailureInfo.badPOP,
                        "validation pop: the given proofOfPossession type is not supported yet");
        }
        return null;
    }
}
