package com.otilm.core.dao.entity;

import com.otilm.api.model.common.NameAndUuidDto;
import com.otilm.api.model.core.location.CertificateInLocationDto;
import com.otilm.api.model.core.location.LocationDto;
import com.otilm.core.attribute.engine.AttributeEngine;
import com.otilm.core.util.DtoMapper;
import com.otilm.core.util.ObjectAccessControlMapper;
import com.fasterxml.jackson.annotation.JsonBackReference;
import com.fasterxml.jackson.annotation.JsonManagedReference;
import jakarta.persistence.*;
import lombok.*;
import org.hibernate.proxy.HibernateProxy;

import java.io.Serial;
import java.io.Serializable;
import java.util.*;

@Getter
@Setter
@ToString
@RequiredArgsConstructor
@Entity
@Table(name = "location")
public class Location extends UniquelyIdentifiedAndAudited implements Serializable, DtoMapper<LocationDto>, ObjectAccessControlMapper<NameAndUuidDto> {

    @Serial
    private static final long serialVersionUID = -5260518684354195007L;

    @Column(name = "name")
    private String name;

    @Column(name = "description")
    private String description;

    @Column(name = "entity_instance_name")
    private String entityInstanceName;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "entity_instance_ref_uuid", insertable = false, updatable = false)
    @ToString.Exclude
    @JsonBackReference
    private EntityInstanceReference entityInstanceReference;

    @Column(name = "entity_instance_ref_uuid")
    private UUID entityInstanceReferenceUuid;

    @Column(name = "enabled")
    private Boolean enabled;

    @OneToMany(
            mappedBy = "location",
            cascade = CascadeType.ALL,
            fetch = FetchType.LAZY
            //orphanRemoval = true
    )
    @JsonManagedReference
    @ToString.Exclude
    private Set<CertificateLocation> certificates = new HashSet<>();

    @Column(name = "support_multi_entries")
    private boolean supportMultipleEntries;

    @Column(name = "support_key_mgmt")
    private boolean supportKeyManagement;

    public void setEntityInstanceReference(EntityInstanceReference entityInstanceReference) {
        this.entityInstanceReference = entityInstanceReference;
        if (entityInstanceReference != null) this.entityInstanceReferenceUuid = entityInstanceReference.getUuid();
        else this.entityInstanceReferenceUuid = null;
    }

    @Override
    @Transient
    public LocationDto mapToDto() {
        LocationDto dto = new LocationDto();
        dto.setUuid(uuid.toString());
        dto.setName(name);
        dto.setDescription(this.description);
        dto.setEntityInstanceUuid(entityInstanceReference != null ? entityInstanceReference.getUuid().toString() : null);
        dto.setEntityInstanceName(this.entityInstanceName);
        dto.setEnabled(enabled);
        dto.setSupportMultipleEntries(supportMultipleEntries);
        dto.setSupportKeyManagement(supportKeyManagement);
        List<CertificateInLocationDto> cilDtoList = new ArrayList<>();

        List<CertificateLocation> orderedList = certificates.stream().sorted(Comparator.comparing(CertificateLocation::getCreated).reversed()).toList();
        for (CertificateLocation certificateLocation : orderedList) {
            CertificateInLocationDto cilDto = new CertificateInLocationDto();
            cilDto.setCommonName(certificateLocation.getCertificate().getCommonName());
            cilDto.setSerialNumber(certificateLocation.getCertificate().getSerialNumber());
            cilDto.setCertificateUuid(certificateLocation.getCertificate().getUuid().toString());
            cilDto.setState(certificateLocation.getCertificate().getState());
            cilDto.setValidationStatus(certificateLocation.getCertificate().getValidationStatus());
            cilDto.setWithKey(certificateLocation.isWithKey());
            cilDto.setPushAttributes(AttributeEngine.getResponseAttributesFromBaseAttributes(certificateLocation.getPushAttributes()));
            cilDto.setCsrAttributes(AttributeEngine.getResponseAttributesFromBaseAttributes(certificateLocation.getCsrAttributes()));

            cilDtoList.add(cilDto);
        }
        dto.setCertificates(cilDtoList);

        return dto;
    }

    @Override
    public NameAndUuidDto mapToAccessControlObjects() {
        return new NameAndUuidDto(uuid.toString(), name);
    }

    public LocationDto mapToDtoSimple() {
        LocationDto dto = new LocationDto();
        dto.setUuid(uuid.toString());
        dto.setName(name);
        dto.setDescription(this.description);
        dto.setEntityInstanceUuid(entityInstanceReference != null ? entityInstanceReference.getUuid().toString() : null);
        dto.setEntityInstanceName(this.entityInstanceName);
        dto.setEnabled(enabled);
        dto.setSupportMultipleEntries(supportMultipleEntries);
        dto.setSupportKeyManagement(supportKeyManagement);
        //TODO - Create a new DTO for the list location operation. Has to be done when creating the objects for other
        // similar operation
        dto.setCertificates(List.of());
        return dto;
    }

    @Override
    public final boolean equals(Object o) {
        if (this == o) return true;
        if (o == null) return false;
        Class<?> oEffectiveClass = o instanceof HibernateProxy ? ((HibernateProxy) o).getHibernateLazyInitializer().getPersistentClass() : o.getClass();
        Class<?> thisEffectiveClass = this instanceof HibernateProxy ? ((HibernateProxy) this).getHibernateLazyInitializer().getPersistentClass() : this.getClass();
        if (thisEffectiveClass != oEffectiveClass) return false;
        Location location = (Location) o;
        return getUuid() != null && Objects.equals(getUuid(), location.getUuid());
    }

    @Override
    public final int hashCode() {
        return this instanceof HibernateProxy ? ((HibernateProxy) this).getHibernateLazyInitializer().getPersistentClass().hashCode() : getClass().hashCode();
    }
}
