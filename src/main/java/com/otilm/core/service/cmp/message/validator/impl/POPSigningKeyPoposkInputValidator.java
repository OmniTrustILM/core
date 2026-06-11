package com.otilm.core.service.cmp.message.validator.impl;

import com.otilm.api.interfaces.core.cmp.error.CmpBaseException;
import com.otilm.api.interfaces.core.cmp.error.CmpProcessingException;
import com.otilm.core.service.cmp.configurations.ConfigurationContext;
import com.otilm.core.service.cmp.message.validator.Validator;
import org.bouncycastle.asn1.cmp.PKIFailureInfo;
import org.bouncycastle.asn1.cmp.PKIMessage;

/**
 * <p>POP validator:
 * if public key and sender are not sent in certTemplate.</p>
 *
 * <pre>
 *    POPOSigningKey ::= SEQUENCE {
 *        poposkInput         [0] POPOSigningKeyInput OPTIONAL,
 *        algorithmIdentifier     AlgorithmIdentifier,
 *        signature               BIT STRING }
 *    </pre>
 * <p>The fields of POPOSigningKey have the following meaning:</p>
 *
 * <p><i>poposkInput</i> contains the data to be signed, when present.  This
 * field MUST be present when the certificate template does not
 * contain both the public key value and a subject name value.<p>
 *
 * <p><i>algorithmIdentifier</i> identifiers the signature algorithm and an
 * associated parameters used to produce the POP value.<p>
 *
 * </p><i>signature</i> contains the POP value produce.  If poposkInput is
 * present, the signature is computed over the DER-encoded value of
 * poposkInput.  If poposkInput is absent, the signature is computed
 * over the DER-encoded value of certReq.<p>
 *
 * <pre>
 *    POPOSigningKeyInput ::= SEQUENCE {
 *        authInfo            CHOICE {
 *            sender              [0] GeneralName,
 *            -- used only if an authenticated identity has been
 *            -- established for the sender (e.g., a DN from a
 *            -- previously-issued and currently-valid certificate)
 *            publicKeyMAC        PKMACValue },
 *            -- used if no authenticated GeneralName currently exists for
 *            -- the sender; publicKeyMAC contains a password-based MAC
 *            -- on the DER-encoded value of publicKey
 *        publicKey           SubjectPublicKeyInfo }  -- from CertTemplate
 *    </pre>
 *
 * <p>
 * The fields of POPOSigningKeyInput have the following meaning:</p>
 *
 * <p>
 * <i>sender</i> contains an authenticated identity that has been previously
 * established for the subject.</p>
 *
 * <p>
 * <i>publicKeyMAC</i> contains a computed value that uses a shared secret
 * between the CA/RA and the certificate requestor.</p>
 *
 * <p>
 * <i>publicKey<i> contains a copy of the public key from the certificate
 * template.  This MUST be exactly the same value as is contained in
 * the certificate template.</p>
 *
 * <pre>
 *    PKMACValue ::= SEQUENCE {
 *       algId  AlgorithmIdentifier,
 *       value  BIT STRING }
 *    </pre>
 *
 * <p>
 * The fields of PKMACValue have the following meaning:</p>
 *
 * <p>
 * algId identifies the algorithm used to compute the MAC value.  All
 * implementations MUST support id-PasswordBasedMAC.  The details on
 * this algorithm are presented in section 4.4.</p>
 *
 * <p>
 * value contains the computed MAC value.  The MAC value is computed
 * over the DER-encoded public key of the certificate subject.</p>
 *
 * <p>The CA/RA identifies the shared secret to be used by looking at 1)
 * the general name field in the certificate request or 2) either the
 * regToken (see section 6.1) or authToken (see section 6.2) controls.</p>
 */
class POPSigningKeyPoposkInputValidator implements Validator<PKIMessage, Void> {
    @Override
    public Void validate(PKIMessage subject, ConfigurationContext configuration) throws CmpBaseException {
        throw new CmpProcessingException(PKIFailureInfo.systemFailure, "not implemented");
    }
}
