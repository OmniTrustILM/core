package com.czertainly.core.dao.entity;

import com.otilm.api.model.common.attribute.common.MetadataAttribute;
import com.otilm.api.model.core.discovery.DiscoveryCertificateDto;
import com.czertainly.core.util.CertificateUtil;
import com.czertainly.core.util.DtoMapper;
import jakarta.persistence.*;
import lombok.*;
import org.hibernate.annotations.JdbcTypeCode;
import org.hibernate.proxy.HibernateProxy;
import org.hibernate.type.SqlTypes;

import java.io.Serial;
import java.io.Serializable;
import java.util.Date;
import java.util.List;
import java.util.Objects;
import java.util.UUID;

@Getter
@Setter
@ToString
@RequiredArgsConstructor
@Entity
@Table(name = "discovery_certificate")
public class DiscoveryCertificate extends UniquelyIdentifiedAndAudited implements Serializable, DtoMapper<DiscoveryCertificateDto> {

    @Serial
    private static final long serialVersionUID = 9115753988094130017L;

    @Column(name = "common_name")
    private String commonName;

    @Column(name = "serial_number")
    private String serialNumber;

    @Column(name = "issuer_common_name")
    private String issuerCommonName;

    @Column(name = "not_before")
    private Date notBefore;

    @Column(name = "not_after")
    private Date notAfter;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "certificate_content_id", nullable = false, insertable = false, updatable = false)
    @ToString.Exclude
    private CertificateContent certificateContent;

    @Column(name = "certificate_content_id", nullable = false)
    private Long certificateContentId;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "discovery_uuid", nullable = false, insertable = false, updatable = false)
    @ToString.Exclude
    private DiscoveryHistory discovery;

    @Column(name = "discovery_uuid", nullable = false)
    private UUID discoveryUuid;

    @Column(name = "newly_discovered", nullable = false)
    private boolean newlyDiscovered;

    @Column(name = "processed", nullable = false)
    private boolean processed;

    @Column(name = "processed_error")
    private String processedError;

    @Column(name = "meta", columnDefinition = "jsonb")
    @JdbcTypeCode(SqlTypes.JSON)
    private List<MetadataAttribute> meta;

    @Override
    public DiscoveryCertificateDto mapToDto() {
        DiscoveryCertificateDto dto = new DiscoveryCertificateDto();
        dto.setUuid(uuid.toString());
        dto.setCommonName(CertificateUtil.formatCommonName(this.commonName));
        dto.setSerialNumber(serialNumber);
        dto.setIssuerCommonName(issuerCommonName);
        dto.setNotBefore(notBefore);
        dto.setNotAfter(notAfter);
        dto.setCertificateContent(certificateContent.getContent());
        dto.setFingerprint(certificateContent.getFingerprint());
        dto.setNewlyDiscovered(newlyDiscovered);
        dto.setProcessed(processed);
        dto.setProcessedError(processedError);
        // Certificate Inventory UUID can be obtained from the content table since it has relation to the certificate.
        // If the certificate is deleted from the inventory and the history is not deleted, then the content remains and
        // the certificate becomes null. Also, the Certificate Content is unique for each certificate and the certificate
        // inventory does not contain duplicate data. Hence, a single content will be mapped to a single certificate using
        // One-to-One relation
        if (certificateContent.getCertificate() != null) {
            dto.setInventoryUuid(certificateContent.getCertificate().getUuid().toString());
        }
        return dto;
    }

    public void setCertificateContent(CertificateContent certificateContent) {
        this.certificateContent = certificateContent;
        this.certificateContentId = certificateContent.getId();
    }

    public void setDiscovery(DiscoveryHistory discovery) {
        this.discovery = discovery;
        this.discoveryUuid = discovery.getUuid();
    }

    @Override
    public final boolean equals(Object o) {
        if (this == o) return true;
        if (o == null) return false;
        Class<?> oEffectiveClass = o instanceof HibernateProxy ? ((HibernateProxy) o).getHibernateLazyInitializer().getPersistentClass() : o.getClass();
        Class<?> thisEffectiveClass = this instanceof HibernateProxy ? ((HibernateProxy) this).getHibernateLazyInitializer().getPersistentClass() : this.getClass();
        if (thisEffectiveClass != oEffectiveClass) return false;
        DiscoveryCertificate that = (DiscoveryCertificate) o;
        return getUuid() != null && Objects.equals(getUuid(), that.getUuid());
    }

    @Override
    public final int hashCode() {
        return this instanceof HibernateProxy ? ((HibernateProxy) this).getHibernateLazyInitializer().getPersistentClass().hashCode() : getClass().hashCode();
    }
}
