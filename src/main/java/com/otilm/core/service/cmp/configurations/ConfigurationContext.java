package com.otilm.core.service.cmp.configurations;

import com.otilm.api.interfaces.core.cmp.error.CmpBaseException;
import com.otilm.api.interfaces.core.cmp.error.CmpConfigurationException;
import com.otilm.api.interfaces.core.cmp.error.CmpProcessingException;
import com.otilm.api.model.client.attribute.RequestAttribute;
import com.otilm.api.model.core.cmp.ProtectionMethod;
import com.otilm.core.dao.entity.Certificate;
import com.otilm.core.dao.entity.RaProfile;
import com.otilm.core.dao.entity.cmp.CmpProfile;
import com.otilm.core.service.cmp.message.protection.ProtectionStrategy;
import java.util.List;
import java.util.function.Predicate;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.cmp.PKIMessage;
import org.bouncycastle.asn1.x509.GeneralName;

public interface ConfigurationContext {

    CmpProfile getCmpProfile();

    RaProfile getRaProfile();

    GeneralName getRecipient();

    ASN1OctetString getSenderKID();

    /**
     * scope: protection (mac-based)
     *
     * @return shared secret for mac-base protection
     */
    byte[] getSharedSecret();

    /**
     * It allows to client define specified validation of CRMF request messages
     *
     * @param request of crmf based message
     */
    void validateOnCrmfRequest(PKIMessage request) throws CmpProcessingException;

    /**
     * It allows to client define specified validation of response messages
     *
     * @param response of message
     */
    void validateOnCrmfResponse(PKIMessage response) throws CmpProcessingException;

    /**
     * @return get protection method (how REQUEST message has to be protected)
     */
    ProtectionMethod getProtectionMethod() throws CmpConfigurationException;

    /**
     * @return get protection strategy (how RESPONSE message has to be protected)
     */
    ProtectionStrategy getProtectionStrategy() throws CmpBaseException;

    List<RequestAttribute> getClientOperationAttributes(boolean isRevoke);

    // to scan extra cert field
    boolean dumpSigning();

    /** Whether the profile authenticates MAC-protected requests against certificate registrations. */
    boolean isRegistrationMode();

    /**
     * Registration mode: resolve {@code senderKID} to a pre-registration, verify the request MAC via the challenge gate
     * (counting/lockout), and stash the matched certificate and its challenge for the handler and response keying.
     * Throws the single generic rejection on any failure.
     *
     * @param macMatches given a candidate challenge key's bytes, whether the request MAC verifies under it
     */
    void verifyRegistrationMacProtection(PKIMessage message, Predicate<byte[]> macMatches) throws CmpBaseException;

    /**
     * The pre-registration matched during protection validation, or {@code null} (not registration mode / unresolved).
     */
    Certificate getMatchedRegistration();

    /** The matched registration's challenge plaintext — the {@code authorizationSecret} for completion. */
    String getMatchedChallenge();

    /**
     * The inventory certificate whose key protects a signature-protected request, set once protection validation has
     * verified the signature and trusts the certificate; {@code null} for a request protected any other way.
     */
    Certificate getProtectionCertificate();

    void setProtectionCertificate(Certificate protectionCertificate);

    /**
     * Whether a signature-protected request is protected by a certificate other than {@code certificate}. A key update
     * and a revocation must be protected by the certificate they act on (RFC 9483 §4.1.3, §4.2).
     */
    default boolean isProtectedByAnotherCertificate(Certificate certificate) {
        Certificate protectionCertificate = getProtectionCertificate();
        return protectionCertificate != null && !protectionCertificate.getUuid().equals(certificate.getUuid());
    }
}
