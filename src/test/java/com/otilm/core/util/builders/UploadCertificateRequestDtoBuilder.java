package com.otilm.core.util.builders;

import com.otilm.api.model.client.certificate.UploadCertificateRequestDto;

import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.util.Base64;
import java.util.List;

public class UploadCertificateRequestDtoBuilder {

    private String certificate = null;

    public static UploadCertificateRequestDtoBuilder anUploadCertificateRequest() {
        return new UploadCertificateRequestDtoBuilder();
    }

    public UploadCertificateRequestDtoBuilder withCertificate(String base64Certificate) {
        this.certificate = base64Certificate;
        return this;
    }

    public UploadCertificateRequestDtoBuilder withCertificate(X509Certificate certificate) throws CertificateEncodingException {
        this.certificate = Base64.getEncoder().encodeToString(certificate.getEncoded());
        return this;
    }

    public UploadCertificateRequestDto build() {
        UploadCertificateRequestDto dto = new UploadCertificateRequestDto();
        dto.setCertificate(certificate);
        dto.setCustomAttributes(List.of());
        return dto;
    }
}
