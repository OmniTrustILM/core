package com.otilm.core.util.builders;

import com.otilm.api.model.core.enums.CertificateRequestFormat;
import com.otilm.core.dao.entity.CertificateRequestEntity;

import java.security.NoSuchAlgorithmException;

/**
 * Builds an in-memory {@link CertificateRequestEntity}; tests override only the fields whose values drive
 * the assertion under test. The request format defaults to {@code PKCS10}. Persistence goes through
 * {@code CertificateRequestRepository}, not this builder.
 */
public class CertificateRequestEntityBuilder {

    private CertificateRequestFormat format = CertificateRequestFormat.PKCS10;
    private String content;

    public static CertificateRequestEntityBuilder aCertificateRequest() {
        return new CertificateRequestEntityBuilder();
    }

    public CertificateRequestEntityBuilder withContent(String content) {
        this.content = content;
        return this;
    }

    public CertificateRequestEntity build() {
        CertificateRequestEntity entity = new CertificateRequestEntity();
        entity.setCertificateRequestFormat(format);
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
