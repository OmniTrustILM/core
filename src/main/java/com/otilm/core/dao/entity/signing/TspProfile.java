package com.otilm.core.dao.entity.signing;

import com.otilm.api.model.core.signing.TspAuthenticationMethod;
import com.otilm.core.dao.entity.UniquelyIdentifiedAndAudited;
import com.otilm.core.dao.entity.VaultProfile;
import com.otilm.core.service.model.Securable;
import jakarta.persistence.CascadeType;
import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.EnumType;
import jakarta.persistence.Enumerated;
import jakarta.persistence.FetchType;
import jakarta.persistence.JoinColumn;
import jakarta.persistence.ManyToOne;
import jakarta.persistence.OneToMany;
import jakarta.persistence.Table;
import lombok.Getter;
import lombok.Setter;
import lombok.ToString;
import org.hibernate.annotations.JdbcTypeCode;
import org.hibernate.type.SqlTypes;

import java.util.ArrayList;
import java.util.List;
import java.util.UUID;

@Getter
@Setter
@Entity
@Table(name = "tsp_profile")
public class TspProfile extends UniquelyIdentifiedAndAudited implements Securable {

    @Getter(onMethod_ = {@Override})
    @Column(name = "name", nullable = false)
    private String name;

    @Column(name = "description")
    private String description;

    @Column(name = "enabled", nullable = false)
    private boolean enabled = false;

    @Column(name = "allowed_authentication_methods", nullable = false)
    @Enumerated(EnumType.STRING)
    @JdbcTypeCode(SqlTypes.ARRAY)
    private List<TspAuthenticationMethod> allowedAuthenticationMethods = new ArrayList<>();

    @OneToMany(mappedBy = "tspProfile", cascade = CascadeType.ALL, orphanRemoval = true, fetch = FetchType.LAZY)
    @ToString.Exclude
    private List<TspProfileBasicCredential> basicCredentials = new ArrayList<>();

    @Column(name = "vault_profile_uuid")
    private UUID vaultProfileUuid;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "vault_profile_uuid", insertable = false, updatable = false)
    @ToString.Exclude
    private VaultProfile vaultProfile;

    public void setVaultProfile(VaultProfile vaultProfile) {
        this.vaultProfile = vaultProfile;
        this.vaultProfileUuid = vaultProfile != null ? vaultProfile.getUuid() : null;
    }

    @Column(name = "default_signing_profile_uuid")
    private UUID defaultSigningProfileUuid;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "default_signing_profile_uuid", insertable = false, updatable = false)
    @ToString.Exclude
    private SigningProfile defaultSigningProfile;

    public void setDefaultSigningProfile(SigningProfile defaultSigningProfile) {
        this.defaultSigningProfile = defaultSigningProfile;
        this.defaultSigningProfileUuid = defaultSigningProfile != null ? defaultSigningProfile.getUuid() : null;
    }

    @Override
    public boolean equals(Object o) {
        return super.equals(o);
    }

    @Override
    public int hashCode() {
        return super.hashCode();
    }
}
