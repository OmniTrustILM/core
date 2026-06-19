package com.otilm.core.dao.entity.oid;

import com.otilm.api.model.core.oid.CertificateExtensionValueEncoding;
import com.otilm.api.model.core.oid.properties.CertificateExtensionOidPropertiesDto;
import jakarta.persistence.Column;
import jakarta.persistence.DiscriminatorValue;
import jakarta.persistence.Entity;
import jakarta.persistence.EnumType;
import jakarta.persistence.Enumerated;
import lombok.Getter;
import lombok.Setter;

@Entity
@Getter
@Setter
@DiscriminatorValue("CERTIFICATE_EXTENSION")
public class CertificateExtensionCustomOidEntry extends CustomOidEntry {

    @Column(name = "default_critical")
    private boolean defaultCritical;

    @Column(name = "value_encoding")
    @Enumerated(EnumType.STRING)
    private CertificateExtensionValueEncoding valueEncoding;

    public CertificateExtensionOidPropertiesDto mapToPropertiesDto() {
        CertificateExtensionOidPropertiesDto dto = new CertificateExtensionOidPropertiesDto();
        dto.setDefaultCritical(defaultCritical);
        dto.setValueEncoding(valueEncoding);
        return dto;
    }
}
