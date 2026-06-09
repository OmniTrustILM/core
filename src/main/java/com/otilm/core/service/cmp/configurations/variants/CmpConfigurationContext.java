package com.otilm.core.service.cmp.configurations.variants;

import com.otilm.api.model.client.attribute.RequestAttribute;
import com.otilm.api.interfaces.core.cmp.error.CmpBaseException;
import com.otilm.api.interfaces.core.cmp.error.CmpProcessingException;
import com.otilm.api.interfaces.core.cmp.error.CmpConfigurationException;
import com.otilm.api.model.core.cmp.ProtectionMethod;
import com.otilm.core.dao.entity.RaProfile;
import com.otilm.core.dao.entity.cmp.CmpProfile;
import com.otilm.core.service.cmp.message.CertificateKeyService;
import com.otilm.core.service.cmp.configurations.ConfigurationContext;
import com.otilm.core.service.cmp.message.protection.ProtectionStrategy;
import com.otilm.core.service.cmp.message.protection.impl.PasswordBasedMacProtectionStrategy;
import com.otilm.core.service.cmp.message.protection.impl.SingatureBaseProtectionStrategy;
import com.otilm.core.util.CertificateUtil;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.cmp.PKIFailureInfo;
import org.bouncycastle.asn1.cmp.PKIMessage;
import org.bouncycastle.asn1.x509.GeneralName;

import java.util.List;

public class CmpConfigurationContext implements ConfigurationContext {

    protected final PKIMessage requestMessage;
    protected final CmpProfile cmpProfile;
    private final RaProfile raProfile;
    private final CertificateKeyService certificateKeyService;
    private final List<RequestAttribute> issueAttributes;
    private final List<RequestAttribute> revokeAttributes;

    public CmpConfigurationContext(CmpProfile cmpProfile, RaProfile raProfile, PKIMessage pkiRequest,
                                   CertificateKeyService certificateKeyServiceImpl,
                                   List<RequestAttribute> issueAttributes,
                                   List<RequestAttribute> revokeAttributes) {
        this.requestMessage = pkiRequest;
        this.cmpProfile = cmpProfile;
        this.raProfile = raProfile;
        this.certificateKeyService = certificateKeyServiceImpl;
        this.issueAttributes = issueAttributes;
        this.revokeAttributes = revokeAttributes;
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
        /* senderKID field MUST hold an identifier
         *    that indicates to the receiver the appropriate shared secret
         *    information to use to verify the message */
        // ASN1OctetString senderKID = requestMessage.getHeader().getSenderKID();
        return getCmpProfile().getSharedSecret().getBytes();
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
