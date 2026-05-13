package com.czertainly.core.dao.entity.signing;

import com.czertainly.core.dao.entity.UniquelyIdentifiedAndAudited;
import com.czertainly.core.service.model.Securable;
import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.FetchType;
import jakarta.persistence.JoinColumn;
import jakarta.persistence.ManyToOne;
import jakarta.persistence.Table;
import lombok.Getter;
import lombok.Setter;
import lombok.ToString;

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
