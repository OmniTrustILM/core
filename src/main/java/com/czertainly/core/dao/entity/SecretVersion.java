package com.czertainly.core.dao.entity;

import com.otilm.api.model.core.secret.SecretVersionDto;
import jakarta.persistence.*;
import lombok.Getter;
import lombok.Setter;
import org.hibernate.annotations.CreationTimestamp;
import org.hibernate.proxy.HibernateProxy;

import java.time.OffsetDateTime;
import java.util.Objects;
import java.util.UUID;

@Entity
@Table(name = "secret_version")
@Getter
@Setter
public class SecretVersion extends UniquelyIdentified {

    @Column(name = "secret_uuid")
    private UUID secretUuid;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "secret_uuid", insertable = false, updatable = false)
    private Secret secret;

    @Column(name = "version", nullable = false)
    private int version;

    @Column(name = "fingerprint", nullable = false)
    private String fingerprint;

    @Column(name = "vault_profile_uuid")
    private UUID vaultProfileUuid;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "vault_profile_uuid", insertable = false, updatable = false)
    private VaultProfile vaultProfile;

    @Column(name = "vault_version")
    private String vaultVersion;

    @Column(name = "i_cre", nullable = false, updatable = false)
    @CreationTimestamp
    private OffsetDateTime createdAt;

    public SecretVersionDto mapToDto() {
        SecretVersionDto dto = new SecretVersionDto();
        dto.setVersion(version);
        dto.setFingerprint(fingerprint);
        dto.setCreatedAt(createdAt);
        return dto;
    }

    @Override
    public final boolean equals(final Object o) {
        if (this == o) return true;
        if (!(o instanceof SecretVersion that)) return false;
        return getUuid() != null && Objects.equals(getUuid(), that.getUuid());
    }

    @Override
    public final int hashCode() {
        return this instanceof HibernateProxy proxy ? proxy.getHibernateLazyInitializer().getPersistentClass().hashCode() : getClass().hashCode();
    }

    public void setSecret(Secret secret) {
        this.secret = secret;
        this.secretUuid = secret == null ? null : secret.getUuid();
    }

    public void setVaultProfile(VaultProfile vaultProfile) {
        this.vaultProfile = vaultProfile;
        this.vaultProfileUuid = vaultProfile == null ? null : vaultProfile.getUuid();
    }

}
