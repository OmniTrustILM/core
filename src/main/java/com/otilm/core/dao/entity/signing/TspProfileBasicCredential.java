package com.otilm.core.dao.entity.signing;

import com.otilm.core.dao.entity.UniquelyIdentified;
import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.FetchType;
import jakarta.persistence.JoinColumn;
import jakarta.persistence.ManyToOne;
import jakarta.persistence.PrePersist;
import jakarta.persistence.Table;
import jakarta.persistence.UniqueConstraint;
import lombok.Getter;
import lombok.Setter;
import lombok.ToString;

import java.util.UUID;

@Getter
@Setter
@ToString
@Entity
@Table(name = "tsp_profile_basic_credential",
        uniqueConstraints = @UniqueConstraint(name = "tsp_profile_basic_credential_username", columnNames = {"tsp_profile_uuid", "username"}))
public class TspProfileBasicCredential extends UniquelyIdentified {

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "tsp_profile_uuid", insertable = false, updatable = false)
    @ToString.Exclude
    private TspProfile tspProfile;

    @Column(name = "tsp_profile_uuid", nullable = false)
    private UUID tspProfileUuid;

    @Column(name = "username", nullable = false)
    private String username;

    @Column(name = "secret_uuid", nullable = false)
    private UUID secretUuid;

    @Column(name = "mapped_user_uuid", nullable = false)
    private UUID mappedUserUuid;

    public void setTspProfile(TspProfile tspProfile) {
        this.tspProfile = tspProfile;
        this.tspProfileUuid = tspProfile != null ? tspProfile.getUuid() : null;
    }

    @PrePersist
    private void syncTspProfileUuid() {
        if (tspProfileUuid == null && tspProfile != null) {
            tspProfileUuid = tspProfile.getUuid();
        }
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
