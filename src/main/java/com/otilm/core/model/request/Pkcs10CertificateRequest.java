package com.otilm.core.model.request;

import com.otilm.api.exception.CertificateRequestException;
import com.otilm.api.model.core.enums.CertificateRequestFormat;
import com.otilm.core.util.CertificateUtil;
import lombok.Getter;
import org.bouncycastle.asn1.pkcs.Attribute;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.*;
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequest;

import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.Map;
import java.util.List;

public class Pkcs10CertificateRequest implements CertificateRequest {

    private final byte[] encoded;
    @Getter
    private final JcaPKCS10CertificationRequest jcaObject;

    public Pkcs10CertificateRequest(byte[] request) throws CertificateRequestException {
        this.encoded = request;
        try {
            this.jcaObject =  new JcaPKCS10CertificationRequest(encoded);
        } catch (Exception e) {
            throw new CertificateRequestException("Cannot process PKCS#10 request", e);
        }
    }

    @Override
    public byte[] getEncoded() {
        return encoded;
    }

    @Override
    public CertificateRequestFormat getFormat() {
        return CertificateRequestFormat.PKCS10;
    }

    @Override
    public X500Name getSubject() {
        return jcaObject.getSubject();
    }

    @Override
    public PublicKey getPublicKey() throws NoSuchAlgorithmException, CertificateRequestException {
        try {
            return jcaObject.getPublicKey();
        } catch (InvalidKeyException e) {
            throw new CertificateRequestException("Cannot get public key from certificate request.", e);
        }
    }

    @Override
    public PublicKey getAltPublicKey() throws NoSuchAlgorithmException, CertificateRequestException {
        Attribute[] attributes = jcaObject.getAttributes();
        for (Attribute attribute : attributes) {
            if (Extension.subjectAltPublicKeyInfo.equals(attribute.getAttrType())) {
                SubjectPublicKeyInfo subjectPublicKeyInfo = SubjectPublicKeyInfo.getInstance(attribute.getAttributeValues()[0]);
                final AlgorithmIdentifier keyAlgorithm = subjectPublicKeyInfo.getAlgorithm();
                X509EncodedKeySpec x509EncodedKeySpec;
                try {
                    x509EncodedKeySpec = new X509EncodedKeySpec(subjectPublicKeyInfo.getEncoded());
                    KeyFactory keyFactory = KeyFactory.getInstance(keyAlgorithm.getAlgorithm().getId());
                    return keyFactory.generatePublic(x509EncodedKeySpec);
                } catch (IOException | InvalidKeySpecException e) {
                    throw new CertificateRequestException("Could not extract alternative public key.", e);
                }
            }
        }
        return null;
    }

    @Override
    public Map<String, List<String>> getSubjectAlternativeNames() {
        return CertificateUtil.getSAN(this);
    }

    @Override
    public AlgorithmIdentifier getSignatureAlgorithm() {
        return jcaObject.getSignatureAlgorithm();
    }

    @Override
    public AlgorithmIdentifier getAltSignatureAlgorithm() {
        Attribute[] attributes = jcaObject.getAttributes();
        for (Attribute attribute : attributes) {
            if (Extension.altSignatureAlgorithm.equals(attribute.getAttrType())) {
                return AlgorithmIdentifier.getInstance(attribute.getAttributeValues()[0]);
            }
        }
        return null;
    }

}
