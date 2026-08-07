package com.otilm.core.service.cmp.configurations.variants;

import com.otilm.api.model.client.attribute.RequestAttribute;
import com.otilm.api.interfaces.core.cmp.error.CmpBaseException;
import com.otilm.api.interfaces.core.cmp.error.CmpProcessingException;
import com.otilm.api.interfaces.core.cmp.error.CmpConfigurationException;
import com.otilm.api.model.core.certificate.CertificateEvent;
import com.otilm.api.model.core.cmp.ProtectionMethod;
import com.otilm.api.model.core.protocol.ProtocolChallengeSource;
import com.otilm.core.dao.entity.Certificate;
import com.otilm.core.dao.entity.RaProfile;
import com.otilm.core.dao.entity.cmp.CmpProfile;
import com.otilm.core.service.cmp.message.CertificateKeyService;
import com.otilm.core.service.cmp.configurations.ConfigurationContext;
import com.otilm.core.service.cmp.message.protection.ProtectionStrategy;
import com.otilm.core.service.cmp.message.protection.impl.PasswordBasedMacProtectionStrategy;
import com.otilm.core.service.cmp.message.protection.impl.SingatureBaseProtectionStrategy;
import com.otilm.core.service.cmp.registration.CmpRegistrationResolver;
import com.otilm.core.util.CertificateUtil;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.cmp.PKIBody;
import org.bouncycastle.asn1.cmp.PKIFailureInfo;
import org.bouncycastle.asn1.cmp.PKIMessage;
import org.bouncycastle.asn1.x509.GeneralName;

import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.function.Predicate;

public class CmpConfigurationContext implements ConfigurationContext {

    protected final PKIMessage requestMessage;
    protected final CmpProfile cmpProfile;
    private final RaProfile raProfile;
    private final CertificateKeyService certificateKeyService;
    private final List<RequestAttribute> issueAttributes;
    private final List<RequestAttribute> revokeAttributes;
    private final CmpRegistrationResolver registrationResolver;

    // Per-request registration state, set when a MAC request resolves in registration mode.
    private Certificate matchedRegistration;
    private String matchedChallenge;

    public CmpConfigurationContext(CmpProfile cmpProfile, RaProfile raProfile, PKIMessage pkiRequest,
                                   CertificateKeyService certificateKeyServiceImpl,
                                   List<RequestAttribute> issueAttributes,
                                   List<RequestAttribute> revokeAttributes) {
        this(cmpProfile, raProfile, pkiRequest, certificateKeyServiceImpl, issueAttributes, revokeAttributes, null);
    }

    public CmpConfigurationContext(CmpProfile cmpProfile, RaProfile raProfile, PKIMessage pkiRequest,
                                   CertificateKeyService certificateKeyServiceImpl,
                                   List<RequestAttribute> issueAttributes,
                                   List<RequestAttribute> revokeAttributes,
                                   CmpRegistrationResolver registrationResolver) {
        this.requestMessage = pkiRequest;
        this.cmpProfile = cmpProfile;
        this.raProfile = raProfile;
        this.certificateKeyService = certificateKeyServiceImpl;
        this.issueAttributes = issueAttributes;
        this.revokeAttributes = revokeAttributes;
        this.registrationResolver = registrationResolver;
    }

    @Override
    public CmpProfile getCmpProfile() {
        return cmpProfile;
    }

    @Override
    public RaProfile getRaProfile() {
        return raProfile;
    }

    /**
     * <b>scope: header template - response part</b>
     *
     * @return pki header recipient
     */
    @Override
    public GeneralName getRecipient() {
        return null; /*requestMessage.getHeader().getRecipient();*/
    }

    /**
     * <b>scope: header template - response part</b>
     *
     * @return pki header recipient
     */
    @Override
    public ASN1OctetString getSenderKID() {
        ASN1OctetString senderKID = requestMessage.getHeader().getSenderKID();
        return senderKID == null ? new DEROctetString(new byte[0]) : senderKID;
    }

    @Override
    public void validateOnCrmfRequest(PKIMessage request) throws CmpProcessingException {
    }

    @Override
    public void validateOnCrmfResponse(PKIMessage response) throws CmpProcessingException {
    }

    @Override
    public ProtectionMethod getProtectionMethod() {
        return getCmpProfile().getRequestProtectionMethod();
    }

    @Override
    public ProtectionStrategy getProtectionStrategy() throws CmpBaseException {
        ProtectionMethod czrtProtectionMethod = getCmpProfile().getResponseProtectionMethod();
        switch (czrtProtectionMethod) {
            case SIGNATURE:
                return new SingatureBaseProtectionStrategy(this,
                        requestMessage.getHeader().getProtectionAlg(), certificateKeyService);
            case SHARED_SECRET:
                byte[] salt = CertificateUtil.generateRandomBytes(20);
                int iterationCount = 1000;
                return new PasswordBasedMacProtectionStrategy(this,
                        requestMessage.getHeader().getProtectionAlg(),
                        getSharedSecret(), salt, iterationCount);
            default:
                throw new CmpConfigurationException(requestMessage.getHeader().getTransactionID(),
                        PKIFailureInfo.systemFailure,
                        "wrong configuration: unknown type of protection strategy, type=" + czrtProtectionMethod);
        }
    }

    @Override
    public byte[] getSharedSecret() {
        if (isRegistrationMode()) {
            // Request path: the protection-matrix check calls this before the MAC is verified — the empty
            // placeholder is only read to inspect the strategy's algorithm, never to protect anything (the
            // request MAC is verified through the gate in verifyRegistrationMacProtection). Response path:
            // after a successful match the matched registration's challenge keys the response MAC.
            return matchedChallenge != null ? matchedChallenge.getBytes(StandardCharsets.UTF_8) : new byte[0];
        }
        return getCmpProfile().getSharedSecret().getBytes();
    }

    @Override
    public boolean isRegistrationMode() {
        return getCmpProfile().getChallengeSource() == ProtocolChallengeSource.CERTIFICATE_REGISTRATION;
    }

    @Override
    public void verifyRegistrationMacProtection(PKIMessage message, Predicate<byte[]> macMatches) throws CmpBaseException {
        ASN1OctetString tid = message.getHeader().getTransactionID();
        if (registrationResolver == null) {
            throw new CmpConfigurationException(tid, PKIFailureInfo.systemFailure,
                    "registration challenge source is configured but the registration resolver is unavailable");
        }
        CmpRegistrationResolver.RegistrationMacResolution resolution = resolveRegistrationMac(message, macMatches, tid);
        this.matchedRegistration = resolution.certificate();
        this.matchedChallenge = resolution.challenge();
    }

    private CmpRegistrationResolver.RegistrationMacResolution resolveRegistrationMac(
            PKIMessage message, Predicate<byte[]> macMatches, ASN1OctetString tid) throws CmpBaseException {
        return switch (message.getBody().getType()) {
            // Enrolment / rekey: strict certificate-state check (a REGISTERED placeholder for ir/cr, the
            // already-issued certificate for kur).
            case PKIBody.TYPE_INIT_REQ, PKIBody.TYPE_CERT_REQ ->
                    registrationResolver.resolveAndVerify(raProfile, getSenderKID(), CertificateEvent.ISSUE, macMatches, tid);
            case PKIBody.TYPE_KEY_UPDATE_REQ ->
                    registrationResolver.resolveAndVerify(raProfile, getSenderKID(), CertificateEvent.REKEY, macMatches, tid);
            // Async follow-ups of a registration exchange: the certificate has moved past REGISTERED by the time
            // the client polls, so the state is not constrained — the MAC is still verified against the
            // registration's surviving challenge and the response keyed by it.
            case PKIBody.TYPE_POLL_REQ, PKIBody.TYPE_CERT_CONFIRM ->
                    registrationResolver.resolveAndVerifyFollowup(raProfile, getSenderKID(), macMatches, tid);
            // Any other MAC body (e.g. a revocation) is not authenticated by a registration challenge.
            default -> throw new CmpProcessingException(tid, PKIFailureInfo.badMessageCheck,
                    CmpRegistrationResolver.REGISTRATION_REJECTION);
        };
    }

    @Override
    public Certificate getMatchedRegistration() {
        return matchedRegistration;
    }

    @Override
    public String getMatchedChallenge() {
        return matchedChallenge;
    }

    @Override
    public List<RequestAttribute> getClientOperationAttributes(boolean isRevoke) {
        return (isRevoke) ? revokeAttributes : issueAttributes;
    }

    @Override
    public boolean dumpSigning() {
        return false; //default: false
    }
}
