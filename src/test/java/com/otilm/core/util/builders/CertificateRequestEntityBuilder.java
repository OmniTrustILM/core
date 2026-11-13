package com.otilm.core.util.builders;

import com.otilm.api.model.core.enums.CertificateRequestFormat;
import com.otilm.core.dao.entity.CertificateRequestEntity;
import com.otilm.core.dao.entity.X509CertificateRequestEntity;
import java.security.NoSuchAlgorithmException;
import java.util.UUID;

/**
 * Builds an in-memory {@link CertificateRequestEntity}; tests override only the fields whose values drive the assertion
 * under test. The request format defaults to {@code PKCS10} and the request certificate type defaults to {@code X509}.
 * Persistence goes through {@code CertificateRequestRepository}, not this builder.
 */
public class CertificateRequestEntityBuilder {

    private CertificateRequestFormat format = CertificateRequestFormat.PKCS10;
    private String content;
    private String subjectDn;
    private String publicKeyAlgorithm;
    private String signatureAlgorithm;
    private UUID keyUuid;
    private UUID altKeyUuid;

    public static CertificateRequestEntityBuilder aCertificateRequest() {
        return new CertificateRequestEntityBuilder();
    }

    public CertificateRequestEntityBuilder withContent(String content) {
        this.content = content;
        return this;
    }

    public CertificateRequestEntityBuilder withSubjectDn(String subjectDn) {
        this.subjectDn = subjectDn;
        return this;
    }

    public CertificateRequestEntityBuilder withPublicKeyAlgorithm(String publicKeyAlgorithm) {
        this.publicKeyAlgorithm = publicKeyAlgorithm;
        return this;
    }

    public CertificateRequestEntityBuilder withSignatureAlgorithm(String signatureAlgorithm) {
        this.signatureAlgorithm = signatureAlgorithm;
        return this;
    }

    public CertificateRequestEntityBuilder withKeyUuid(UUID keyUuid) {
        this.keyUuid = keyUuid;
        return this;
    }

    public CertificateRequestEntityBuilder withAltKeyUuid(UUID altKeyUuid) {
        this.altKeyUuid = altKeyUuid;
        return this;
    }

    public X509CertificateRequestEntity build() {
        X509CertificateRequestEntity entity = new X509CertificateRequestEntity();
        entity.setCertificateRequestFormat(format);
        if (subjectDn != null) {
            entity.setSubjectDn(subjectDn);
        }
        if (publicKeyAlgorithm != null) {
            entity.setPublicKeyAlgorithm(publicKeyAlgorithm);
        }
        if (signatureAlgorithm != null) {
            entity.setSignatureAlgorithm(signatureAlgorithm);
        }
        if (keyUuid != null) {
            entity.setKeyUuid(keyUuid);
        }
        if (altKeyUuid != null) {
            entity.setAltKeyUuid(altKeyUuid);
        }
        if (content != null) {
            // setContent fingerprints the content and so declares NoSuchAlgorithmException; wrap it unchecked
            try {
                entity.setContent(content);
            } catch (NoSuchAlgorithmException e) {
                throw new IllegalStateException("Failed to set certificate request content", e);
            }
        }
        return entity;
    }
}
