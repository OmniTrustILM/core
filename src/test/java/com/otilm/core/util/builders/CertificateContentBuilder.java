package com.otilm.core.util.builders;

import com.otilm.core.dao.entity.CertificateContent;

/**
 * Builds an in-memory {@link CertificateContent}; tests override only the fields whose values drive the
 * assertion under test. Persistence goes through {@code CertificateContentRepository}, not this builder.
 */
public class CertificateContentBuilder {

    private String content;
    private String fingerprint;

    public static CertificateContentBuilder aCertificateContent() {
        return new CertificateContentBuilder();
    }

    public CertificateContentBuilder withContent(String content) {
        this.content = content;
        return this;
    }

    public CertificateContentBuilder withFingerprint(String fingerprint) {
        this.fingerprint = fingerprint;
        return this;
    }

    public CertificateContent build() {
        CertificateContent certificateContent = new CertificateContent();
        if (content != null) certificateContent.setContent(content);
        if (fingerprint != null) certificateContent.setFingerprint(fingerprint);
        return certificateContent;
    }
}
