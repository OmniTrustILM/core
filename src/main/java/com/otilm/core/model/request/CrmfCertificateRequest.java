package com.otilm.core.model.request;

import com.otilm.api.exception.CertificateRequestException;
import com.otilm.api.model.core.enums.CertificateRequestFormat;
import com.otilm.core.util.CertificateUtil;
import com.otilm.core.util.CryptographyUtil;
import java.io.IOException;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.util.List;
import java.util.Map;
import lombok.Getter;
import org.bouncycastle.asn1.crmf.CertReqMessages;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.Extensions;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.cert.crmf.jcajce.JcaCertificateRequestMessage;

public class CrmfCertificateRequest implements CertificateRequest {

    private final byte[] encoded;
    @Getter
    private final JcaCertificateRequestMessage certificateRequestMessage;

    public CrmfCertificateRequest(byte[] request) throws CertificateRequestException {
        this.encoded = request;
        try {
            CertReqMessages certReqMessages = CertReqMessages.getInstance(request);
            // we take only the first request
            // TODO: support multiple requests
            this.certificateRequestMessage = new JcaCertificateRequestMessage(certReqMessages.toCertReqMsgArray()[0]);
        } catch (Exception e) {
            throw new CertificateRequestException("Cannot process CRMF request", e);
        }
    }

    @Override
    public byte[] getEncoded() {
        return encoded;
    }

    @Override
    public CertificateRequestFormat getFormat() {
        return CertificateRequestFormat.CRMF;
    }

    @Override
    public X500Name getSubject() {
        return certificateRequestMessage.getCertTemplate().getSubject();
    }

    @Override
    public PublicKey getPublicKey() throws NoSuchAlgorithmException, CertificateRequestException {
        SubjectPublicKeyInfo subjectPublicKeyInfo = certificateRequestMessage.getCertTemplate().getPublicKey();
        if (subjectPublicKeyInfo == null) {
            throw new CertificateRequestException("Cannot get public key from certificate request.");
        }
        try {
            return CryptographyUtil.decodePublicKey(subjectPublicKeyInfo.getEncoded());
        } catch (IOException | InvalidKeySpecException e) {
            throw new CertificateRequestException("Cannot get public key from certificate request.", e);
        }
    }

    @Override
    public PublicKey getAltPublicKey() throws NoSuchAlgorithmException, CertificateRequestException {
        return null;
    }

    @Override
    public Map<String, List<String>> getSubjectAlternativeNames() {
        return CertificateUtil.getSAN(this);
    }

    @Override
    public AlgorithmIdentifier getSignatureAlgorithm() {
        return certificateRequestMessage.getCertTemplate().getSigningAlg();
    }

    @Override
    public AlgorithmIdentifier getAltSignatureAlgorithm() {
        return null;
    }

    /** Extensions carried in the CRMF {@code CertTemplate}, or {@code null} when none are present. */
    public Extensions getCertTemplateExtensions() {
        return certificateRequestMessage.getCertTemplate().getExtensions();
    }

}
