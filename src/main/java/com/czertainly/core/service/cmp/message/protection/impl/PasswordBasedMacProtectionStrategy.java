package com.czertainly.core.service.cmp.message.protection.impl;

import com.otilm.api.interfaces.core.cmp.error.CmpBaseException;
import com.otilm.api.interfaces.core.cmp.error.CmpProcessingException;
import com.otilm.api.interfaces.core.cmp.error.CmpConfigurationException;
import com.czertainly.core.service.cmp.configurations.ConfigurationContext;
import com.czertainly.core.service.cmp.message.protection.ProtectionStrategy;
import org.bouncycastle.asn1.ASN1Encoding;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.DERBitString;
import org.bouncycastle.asn1.cmp.*;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.DefaultDigestAlgorithmIdentifierFinder;
import org.bouncycastle.operator.DefaultMacAlgorithmIdentifierFinder;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.io.IOException;
import java.security.MessageDigest;
import java.util.List;

/**
 * Implementation of password-based protection of {@link PKIMessage}.
 *
 * @see <a href="https://www.rfc-editor.org/rfc/rfc4210#section-5.1.3.1">Shared Secret Information, at rfc4210</a>
 */
public class PasswordBasedMacProtectionStrategy extends BaseProtectionStrategy implements ProtectionStrategy {

    private final DefaultDigestAlgorithmIdentifierFinder DIGEST_ALGORITHM_IDENTIFIER_FINDER =
            new DefaultDigestAlgorithmIdentifierFinder();
    private final DefaultMacAlgorithmIdentifierFinder MAC_ALGORITHM_IDENTIFIER_FINDER =
            new DefaultMacAlgorithmIdentifierFinder();

    private final Mac mac;
    private final AlgorithmIdentifier protectionAlgorithm;

    public PasswordBasedMacProtectionStrategy(ConfigurationContext configuration,
                                              AlgorithmIdentifier headerProtectionAlgorithm,
                                              byte[] sharedSecret,
                                              byte[] protectionSalt,
                                              int iterationCount)
            throws CmpBaseException {
        super(configuration, headerProtectionAlgorithm);
        byte[] calculatingBaseKey = new byte[sharedSecret.length + protectionSalt.length];
        System.arraycopy(sharedSecret, 0, calculatingBaseKey, 0, sharedSecret.length);
        System.arraycopy(protectionSalt, 0, calculatingBaseKey, sharedSecret.length, protectionSalt.length);

        try {
            AlgorithmIdentifier digestAlgorithm = getDigestAlgorithm();
            MessageDigest digest = MessageDigest.getInstance(digestAlgorithm.getAlgorithm().getId(),
                    BouncyCastleProvider.PROVIDER_NAME);
            for (int i = 0; i < iterationCount; i++) {
                calculatingBaseKey = digest.digest(calculatingBaseKey);
                digest.reset();
            }

            AlgorithmIdentifier macAlgorithm = getMacAlgorithm();
            this.mac = Mac.getInstance(macAlgorithm.getAlgorithm().getId(),
                    BouncyCastleProvider.PROVIDER_NAME);
            this.mac.init(new SecretKeySpec(calculatingBaseKey, mac.getAlgorithm()));
            this.protectionAlgorithm = new AlgorithmIdentifier(
                    CMPObjectIdentifiers.passwordBasedMac,
                    new PBMParameter(
                            protectionSalt,
                            digestAlgorithm,
                            iterationCount,
                            macAlgorithm));
        } catch (Exception e) {
            throw new CmpProcessingException(null, PKIFailureInfo.systemFailure,
                    "cannot initialize of password based mac strategy", e);
        }
    }

    @Override
    public AlgorithmIdentifier getProtectionAlg() throws CmpConfigurationException {
        return protectionAlgorithm;
    }

    @Override
    public DERBitString createProtection(PKIHeader header, PKIBody body) throws IOException {
        mac.update(new ProtectedPart(header, body).getEncoded(ASN1Encoding.DER));
        byte[] protectionBytes = mac.doFinal();
        mac.reset();
        return new DERBitString(protectionBytes);
    }

    @Override
    public List<CMPCertificate> getProtectingExtraCerts() throws Exception {
        return null;
    }

    @Override
    public GeneralName getSender() {
        return null;
    }

    @Override
    public ASN1OctetString getSenderKID() {
        return configuration.getSenderKID();
    }

    private AlgorithmIdentifier getDigestAlgorithm() throws CmpConfigurationException {
        PBMParameter pbmParameter = PBMParameter.getInstance(
                headerProtectionAlgorithm.getParameters());
        AlgorithmIdentifier algorithmIdentifier = pbmParameter.getOwf();
        if (algorithmIdentifier == null) {
            algorithmIdentifier = DIGEST_ALGORITHM_IDENTIFIER_FINDER.find("SHA256");//db query/cmp profile.getSignatureName
            if (algorithmIdentifier == null) {
                throw new CmpConfigurationException(PKIFailureInfo.systemFailure, "wrong name of DIGEST algorithm");
            }
        }
        return algorithmIdentifier;
    }

    /**
     * scope: PasswordBased-MAC  Protection
     *
     * @return algorithm for mac (for PKI Protection field)
     * @throws CmpConfigurationException if algorithm cannot be found (e.g. wrong mac name).
     */
    private AlgorithmIdentifier getMacAlgorithm() throws CmpConfigurationException {
        PBMParameter pbmParameter = PBMParameter.getInstance(
                headerProtectionAlgorithm.getParameters());
        AlgorithmIdentifier algorithmIdentifier = pbmParameter.getMac();
        if (algorithmIdentifier == null) {
            algorithmIdentifier = MAC_ALGORITHM_IDENTIFIER_FINDER.find("HMACSHA256");//db query/cmp profile.getSignatureName
            if (algorithmIdentifier == null) {
                throw new CmpConfigurationException(PKIFailureInfo.systemFailure, "wrong name of MAC algorithm");
            }
        }
        return algorithmIdentifier;
    }
}
