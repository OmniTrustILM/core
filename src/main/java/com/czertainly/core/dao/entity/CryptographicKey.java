package com.czertainly.core.dao.entity;

import com.otilm.api.model.core.auth.Resource;
import com.otilm.api.model.core.compliance.ComplianceStatus;
import com.otilm.api.model.core.cryptography.key.*;
import com.czertainly.core.util.DtoMapper;
import com.fasterxml.jackson.annotation.JsonBackReference;
import jakarta.persistence.*;
import lombok.*;
import org.hibernate.annotations.SQLJoinTableRestriction;
import org.hibernate.proxy.HibernateProxy;

import java.io.Serializable;
import java.util.*;

@Getter
@Setter
@ToString
@RequiredArgsConstructor
@Entity
@Table(name = "cryptographic_key")
public class CryptographicKey extends UniquelyIdentifiedAndAudited implements Serializable, DtoMapper<KeyDto> {

    @Column(name = "name")
    private String name;

    @Column(name = "description")
    private String description;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "token_profile_uuid", insertable = false, updatable = false)
    @ToString.Exclude
    private TokenProfile tokenProfile;

    @Column(name = "token_profile_uuid")
    private UUID tokenProfileUuid;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "token_instance_uuid", insertable = false, updatable = false)
    @ToString.Exclude
    private TokenInstanceReference tokenInstanceReference;

    @Column(name = "token_instance_uuid")
    private UUID tokenInstanceReferenceUuid;

    @ManyToMany(fetch = FetchType.LAZY)
    @JoinTable(
            name = "group_association",
            joinColumns = @JoinColumn(name = "object_uuid", referencedColumnName = "uuid", insertable = false, updatable = false, foreignKey = @ForeignKey(ConstraintMode.NO_CONSTRAINT)),
            inverseJoinColumns = @JoinColumn(name = "group_uuid", insertable = false, updatable = false)
    )
    @SQLJoinTableRestriction("resource = 'CRYPTOGRAPHIC_KEY'")
    @ToString.Exclude
    private Set<Group> groups = new HashSet<>();

    @OneToOne(fetch = FetchType.LAZY, mappedBy = "key")
    @ToString.Exclude
    private OwnerAssociation owner;

    @JsonBackReference
    @OneToMany(mappedBy = "key", cascade = CascadeType.ALL, fetch = FetchType.LAZY)
    @ToString.Exclude
    private Set<CryptographicKeyItem> items = new HashSet<>();

    @JsonBackReference
    @OneToMany(mappedBy = "key", fetch = FetchType.LAZY)
    @ToString.Exclude
    private Set<Certificate> certificates = new HashSet<>();

    @JsonBackReference
    @OneToMany(mappedBy = "altKey", fetch = FetchType.LAZY)
    @ToString.Exclude
    private Set<Certificate> altCertificates = new HashSet<>();

    public void setTokenProfile(TokenProfile tokenProfile) {
        this.tokenProfile = tokenProfile;
        if (tokenProfile != null) this.tokenProfileUuid = tokenProfile.getUuid();
    }

    public void setTokenInstanceReference(TokenInstanceReference tokenInstanceReference) {
        this.tokenInstanceReference = tokenInstanceReference;
        if (tokenInstanceReference != null) this.tokenInstanceReferenceUuid = tokenInstanceReference.getUuid();
    }

    // Get the list of items for the key
    public List<KeyItemDetailDto> getKeyItems() {
        return items.stream().map(CryptographicKeyItem::mapToDto).toList();
    }

    // Get the list of items for the key
    public List<KeyItemDto> getKeyItemsSummary() {
        return items.stream().map(CryptographicKeyItem::mapToSummaryDto).toList();
    }

    @Override
    public KeyDto mapToDto() {
        KeyDto dto = buildKeyDto();
        dto.setAssociations((items.size() - 1) + certificates.size() + altCertificates.size());
        return dto;
    }

    /**
     * Lightweight variant of {@link #mapToDto()} for use in chain responses.
     * Omits {@code associations} to avoid initializing the lazy {@code certificates} and {@code altCertificates} collections.
     */
    public KeyDto mapToChainDto() {
        return buildKeyDto();
    }

    /**
     * Populates a {@link KeyDto} with all fields except {@code associations}.
     */
    private KeyDto buildKeyDto() {
        KeyDto dto = new KeyDto();
        dto.setName(name);
        dto.setUuid(uuid.toString());
        dto.setDescription(description);
        dto.setCreationTime(created);
        if (tokenProfile != null) {
            dto.setTokenProfileName(tokenProfile.getName());
            dto.setTokenProfileUuid(tokenProfile.getUuid().toString());
        }
        if (tokenInstanceReference != null) {
            dto.setTokenInstanceName(tokenInstanceReference.getName());
            dto.setTokenInstanceUuid(tokenInstanceReferenceUuid.toString());
        }
        if (groups != null) {
            dto.setGroups(groups.stream().map(Group::mapToDto).toList());
        }
        if (owner != null) {
            dto.setOwnerUuid(owner.getOwnerUuid().toString());
            dto.setOwner(owner.getOwnerUsername());
        }
        dto.setItems(getKeyItemsSummary());
        dto.setComplianceStatus(getComplianceStatus());
        return dto;
    }

    private ComplianceStatus getComplianceStatus() {
        if (items.isEmpty()) {
            return ComplianceStatus.NOT_CHECKED;
        }
        List<ComplianceStatus> statuses = items.stream()
                .map(CryptographicKeyItem::getComplianceStatus)
                .filter(Objects::nonNull)
                .toList();
        if (statuses.isEmpty()) {
            return ComplianceStatus.NOT_CHECKED;
        }
        if (statuses.contains(ComplianceStatus.NOK)) {
            return ComplianceStatus.NOK;
        } else if (statuses.contains(ComplianceStatus.FAILED)) {
            return ComplianceStatus.FAILED;
        } else if (statuses.contains(ComplianceStatus.NA)) {
            return ComplianceStatus.NA;
        } else if (statuses.contains(ComplianceStatus.NOT_CHECKED)) {
            return ComplianceStatus.NOT_CHECKED;
        } else {
            return ComplianceStatus.OK;
        }
    }

    public KeyDetailDto mapToDetailDto() {
        KeyDetailDto dto = new KeyDetailDto();
        dto.setName(name);
        dto.setUuid(uuid.toString());
        dto.setDescription(description);
        dto.setCreationTime(created);
        dto.setComplianceStatus(getComplianceStatus());
        if (tokenProfile != null) {
            dto.setTokenProfileName(tokenProfile.getName());
            dto.setTokenProfileUuid(tokenProfile.getUuid().toString());
        }
        if (tokenInstanceReference != null) {
            dto.setTokenInstanceName(tokenInstanceReference.getName());
            dto.setTokenInstanceUuid(tokenInstanceReferenceUuid.toString());
        }
        dto.setItems(getKeyItems());
        if (groups != null) {
            dto.setGroups(groups.stream().map(Group::mapToDto).toList());
        }
        if (owner != null) {
            dto.setOwnerUuid(owner.getOwnerUuid().toString());
            dto.setOwner(owner.getOwnerUsername());
        }
        List<KeyAssociationDto> keyAssociationDtos = new ArrayList<>();
        if (certificates != null && !certificates.isEmpty()) {
            keyAssociationDtos.addAll(certificates.stream().map(e -> {
                KeyAssociationDto keyAssociationDto = new KeyAssociationDto();
                keyAssociationDto.setName(e.getCommonName());
                keyAssociationDto.setUuid(e.getUuid().toString());
                keyAssociationDto.setResource(Resource.CERTIFICATE);
                return keyAssociationDto;
            }).toList());
        }

        if (altCertificates != null && !altCertificates.isEmpty()) {
            keyAssociationDtos.addAll(altCertificates.stream().map(e -> {
                KeyAssociationDto keyAssociationDto = new KeyAssociationDto();
                keyAssociationDto.setName(e.getCommonName());
                keyAssociationDto.setUuid(e.getUuid().toString());
                keyAssociationDto.setResource(Resource.CERTIFICATE);
                return keyAssociationDto;
            }).toList());
        }
        dto.setAssociations(keyAssociationDtos);
        return dto;
    }

    @Override
    public final boolean equals(Object o) {
        if (this == o) return true;
        if (o == null) return false;
        Class<?> oEffectiveClass = o instanceof HibernateProxy proxy ? proxy.getHibernateLazyInitializer().getPersistentClass() : o.getClass();
        Class<?> thisEffectiveClass = this instanceof HibernateProxy proxy ? proxy.getHibernateLazyInitializer().getPersistentClass() : this.getClass();
        if (thisEffectiveClass != oEffectiveClass) return false;
        if (!(o instanceof CryptographicKey that)) return false;
        return getUuid() != null && Objects.equals(getUuid(), that.getUuid());
    }

    @Override
    public final int hashCode() {
        return this instanceof HibernateProxy proxy ? proxy.getHibernateLazyInitializer().getPersistentClass().hashCode() : getClass().hashCode();
    }
}
