package com.czertainly.core.dao.entity;

import java.time.OffsetDateTime;
import java.util.Objects;

import org.hibernate.annotations.CreationTimestamp;
import org.hibernate.proxy.HibernateProxy;

import com.otilm.api.model.core.cbom.CbomDto;
import com.czertainly.core.util.DtoMapper;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Table;
import lombok.Getter;
import lombok.RequiredArgsConstructor;
import lombok.Setter;
import lombok.ToString;

@Getter
@Setter
@ToString
@RequiredArgsConstructor
@Entity
@Table(name = "cbom")
public class Cbom extends UniquelyIdentified implements DtoMapper<CbomDto> {
    @CreationTimestamp
    @Column(name = "created_at", nullable = false, updatable = false)
    private OffsetDateTime createdAt;

    @Column(name = "serial_number", nullable = false)
    private String serialNumber;

    @Column(name = "version", nullable = false)
    private int version;

    @Column(name = "spec_version", nullable = false)
    private String specVersion;

    @Column(name = "timestamp", nullable = true, updatable = false)
    private OffsetDateTime timestamp;

    @Column(name = "source", nullable = true)
    private String source;

    @Column(name = "algorithms_count", nullable = false)
    private int algorithmsCount;

    @Column(name = "certificates_count", nullable = false)
    private int certificatesCount;

    @Column(name = "protocols_count", nullable = false)
    private int protocolsCount;

    @Column(name = "crypto_material_count", nullable = false)
    private int cryptoMaterialCount;

    @Column(name = "total_assets_count", nullable = false)
    private int totalAssetsCount;

    @Override
    public CbomDto mapToDto() {
        CbomDto dto = new CbomDto();

        dto.setUuid(this.uuid);
        dto.setCreatedAt(this.createdAt);
        dto.setSerialNumber(this.serialNumber);
        dto.setVersion(this.version);
        dto.setSpecVersion(this.specVersion);
        dto.setTimestamp(this.timestamp);
        dto.setSource(this.source);
        dto.setAlgorithms(this.algorithmsCount);
        dto.setCertificates(this.certificatesCount);
        dto.setProtocols(this.protocolsCount);
        dto.setCryptoMaterial(this.cryptoMaterialCount);
        dto.setTotalAssets(this.totalAssetsCount);
        return dto;
    }

    @Override
    public final boolean equals(Object o) {
        if (this == o) return true;
        if (o == null) return false;
        Class<?> oEffectiveClass = o instanceof HibernateProxy hibernateProxy 
        ? hibernateProxy.getHibernateLazyInitializer().getPersistentClass() 
        : o.getClass();
        Class<?> thisEffectiveClass = this instanceof HibernateProxy hibernateProxy 
        ? hibernateProxy.getHibernateLazyInitializer().getPersistentClass() 
        : this.getClass();
        if (thisEffectiveClass != oEffectiveClass) return false;
        Cbom that = (Cbom) o;
        return getUuid() != null && Objects.equals(getUuid(), that.getUuid());
    }

    @Override
    public final int hashCode() {
        return this instanceof HibernateProxy proxy ? proxy.getHibernateLazyInitializer().getPersistentClass().hashCode() : getClass().hashCode();
    }
}
