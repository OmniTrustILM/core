package com.otilm.core.util.builders;

import com.otilm.api.model.client.attribute.RequestAttribute;
import com.otilm.api.model.client.certificate.UploadCertificateRequestDto;

import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.util.Base64;
import java.util.List;

public class UploadCertificateRequestDtoBuilder {

    private String certificate = null;
    private List<RequestAttribute> customAttributes = List.of();

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

    public UploadCertificateRequestDtoBuilder withCustomAttributes(List<RequestAttribute> customAttributes) {
        this.customAttributes = customAttributes;
        return this;
    }

    public UploadCertificateRequestDto build() {
        UploadCertificateRequestDto dto = new UploadCertificateRequestDto();
        dto.setCertificate(certificate);
        dto.setCustomAttributes(customAttributes);
        return dto;
    }
}
