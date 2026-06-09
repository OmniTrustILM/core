package com.czertainly.core.dao.entity;

import com.otilm.api.model.common.NameAndUuidDto;
import com.otilm.api.model.common.enums.IPlatformEnum;
import com.otilm.api.model.connector.secrets.SecretType;
import com.otilm.api.model.core.compliance.ComplianceStatus;
import com.otilm.api.model.core.secret.SecretDetailDto;
import com.otilm.api.model.core.secret.SecretDto;
import com.otilm.api.model.core.secret.SecretState;
import com.otilm.api.model.core.secret.SyncVaultProfileDto;
import com.czertainly.core.attribute.engine.AttributeEngine;
import com.czertainly.core.model.compliance.ComplianceResultDto;
import com.fasterxml.jackson.annotation.JsonBackReference;
import jakarta.persistence.*;
import lombok.*;
import org.hibernate.annotations.JdbcTypeCode;
import org.hibernate.annotations.SQLJoinTableRestriction;
import org.hibernate.proxy.HibernateProxy;
import org.hibernate.type.SqlTypes;

import java.util.HashSet;
import java.util.Objects;
import java.util.Set;
import java.util.UUID;

@Entity
@Table(name = "secret")
@Getter
@Setter
public class Secret extends UniquelyIdentifiedAndAudited implements ComplianceSubject {

    @Column(name = "name", nullable = false)
    private String name;

    @Column(name = "description")
    private String description;

    @Column(name = "source_vault_profile_uuid", nullable = false)
    private UUID sourceVaultProfileUuid;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "source_vault_profile_uuid", nullable = false, insertable = false, updatable = false)
    @ToString.Exclude
    @JsonBackReference
    private VaultProfile sourceVaultProfile;

    @OneToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "latest_version_uuid", insertable = false, updatable = false)
    @ToString.Exclude
    @JsonBackReference
    private SecretVersion latestVersion;

    @Column(name = "latest_version_uuid", nullable = false)
    private UUID latestVersionUuid;

    @OneToMany(mappedBy = "secret", fetch = FetchType.LAZY)
    @ToString.Exclude
    @JsonBackReference
    @OrderBy("version DESC")
    private Set<SecretVersion> versions = new HashSet<>();

    @Column(name = "type", nullable = false)
    @Enumerated(EnumType.STRING)
    private SecretType type;

    @Column(name = "state", nullable = false)
    @Enumerated(EnumType.STRING)
    private SecretState state;

    @Column(name = "enabled", nullable = false)
    private boolean enabled;

    @ManyToMany(fetch = FetchType.LAZY)
    @JoinTable(
            name = "group_association",
            joinColumns = @JoinColumn(name = "object_uuid", referencedColumnName = "uuid", insertable = false, updatable = false, foreignKey = @ForeignKey(ConstraintMode.NO_CONSTRAINT)),
            inverseJoinColumns = @JoinColumn(name = "group_uuid", insertable = false, updatable = false)
    )
    @SQLJoinTableRestriction("resource = 'SECRET'")
    @ToString.Exclude
    private Set<Group> groups = new HashSet<>();

    @OneToOne(mappedBy = "secret")
    @ToString.Exclude
    private OwnerAssociation owner;

    @OneToMany(mappedBy = "secret", fetch = FetchType.LAZY, cascade = CascadeType.REMOVE, orphanRemoval = true)
    @JsonBackReference
    @ToString.Exclude
    private Set<Secret2SyncVaultProfile> syncVaultProfiles = new HashSet<>();

    @Column(name = "compliance_result", columnDefinition = "jsonb")
    @JdbcTypeCode(SqlTypes.JSON)
    private ComplianceResultDto complianceResult;

    @Column(name = "compliance_status", nullable = false)
    @Enumerated(EnumType.STRING)
    private ComplianceStatus complianceStatus = ComplianceStatus.NOT_CHECKED;

    public SecretDetailDto mapToDetailDto() {
        SecretDetailDto dto = new SecretDetailDto();
        setCommonFields(dto);
        dto.setSyncVaultProfiles(syncVaultProfiles.stream().map(p -> {
            SyncVaultProfileDto vaultProfileDto = new SyncVaultProfileDto();
            vaultProfileDto.setSecretAttributes(AttributeEngine.getResponseAttributesFromRequestAttributes(p.getSecretAttributes()));
            vaultProfileDto.setName(p.getVaultProfile().getName());
            vaultProfileDto.setUuid(p.getVaultProfile().getUuid().toString());
            return vaultProfileDto;
        }).toList());
        dto.setCreatedAt(created);
        dto.setUpdatedAt(updated);
        return dto;
    }

    public SecretDto mapToDto() {
        SecretDto dto = new SecretDto();
        setCommonFields(dto);
        return dto;
    }

    private void setCommonFields(SecretDto secretDto) {
        secretDto.setUuid(String.valueOf(uuid));
        secretDto.setName(name);
        secretDto.setDescription(description);
        secretDto.setType(type);
        secretDto.setState(state);
        secretDto.setEnabled(enabled);
        secretDto.setVersion(versions.stream().filter(v -> v.getUuid().equals(latestVersionUuid)).findFirst().map(SecretVersion::getVersion).orElse(0));
        secretDto.setSourceVaultProfile(new NameAndUuidDto(sourceVaultProfile.getUuid().toString(), sourceVaultProfile.getName()));
        if (owner != null) {
            secretDto.setOwner(new NameAndUuidDto(owner.getOwnerUuid().toString(), owner.getOwnerUsername()));
        }
        secretDto.setGroups(groups.stream().map(g -> new NameAndUuidDto(g.getUuid().toString(), g.getName())).toList());
        secretDto.setComplianceStatus(complianceStatus);
    }

    @Override
    public final boolean equals(final Object o) {
        if (this == o) return true;
        if (!(o instanceof Secret that)) return false;
        return getUuid() != null && Objects.equals(getUuid(), that.getUuid());
    }

    @Override
    public final int hashCode() {
        return this instanceof HibernateProxy proxy ? proxy.getHibernateLazyInitializer().getPersistentClass().hashCode() : getClass().hashCode();
    }

    public void setSourceVaultProfile(VaultProfile sourceVaultProfile) {
        this.sourceVaultProfile = sourceVaultProfile;
        this.sourceVaultProfileUuid = sourceVaultProfile.getUuid();
    }

    public void setLatestVersion(SecretVersion latestVersion) {
        this.latestVersion = latestVersion;
        this.latestVersionUuid = latestVersion == null ? null : latestVersion.getUuid();
    }

    @Override
    public IPlatformEnum getFormat() {
        return null;
    }

    @Override
    public String getContentData() {
        return "";
    }
}
