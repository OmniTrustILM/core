package com.otilm.core.dao.entity;

import com.otilm.api.exception.NotFoundException;
import com.fasterxml.jackson.annotation.JsonBackReference;
import jakarta.persistence.*;
import lombok.*;
import org.hibernate.proxy.HibernateProxy;

import java.util.*;

@Getter
@Setter
@ToString
@RequiredArgsConstructor
@Entity
@Table(name = "approval_profile")
public class ApprovalProfile extends UniquelyIdentifiedAndAudited {

    @Column(name = "name")
    private String name;

    @JsonBackReference
    @OneToMany(mappedBy = "approvalProfile", fetch = FetchType.LAZY)
    @ToString.Exclude
    private List<ApprovalProfileVersion> approvalProfileVersions = new ArrayList<>();

    @OneToMany(mappedBy = "approvalProfile", fetch = FetchType.LAZY)
    @ToString.Exclude
    private List<ApprovalProfileRelation> approvalProfileRelations = new ArrayList<>();

    @JsonBackReference
    public ApprovalProfileVersion getTheLatestApprovalProfileVersion() {
        return getApprovalProfileVersions().stream()
                .max(Comparator.comparingInt(ApprovalProfileVersion::getVersion))
                .orElse(null);
    }

    public ApprovalProfileVersion getApprovalProfileVersionByVersion(final int version) throws NotFoundException {
        Optional<ApprovalProfileVersion> approvalProfileVersion = getApprovalProfileVersions().stream().filter(apv -> apv.getVersion() == version).findFirst();
        if (approvalProfileVersion.isEmpty()) {
            throw new NotFoundException("Unable to find approval profile version with version " + version);
        }
        return approvalProfileVersion.get();
    }

    @Override
    public final boolean equals(Object o) {
        if (this == o) return true;
        if (o == null) return false;
        Class<?> oEffectiveClass = o instanceof HibernateProxy ? ((HibernateProxy) o).getHibernateLazyInitializer().getPersistentClass() : o.getClass();
        Class<?> thisEffectiveClass = this instanceof HibernateProxy ? ((HibernateProxy) this).getHibernateLazyInitializer().getPersistentClass() : this.getClass();
        if (thisEffectiveClass != oEffectiveClass) return false;
        ApprovalProfile that = (ApprovalProfile) o;
        return getUuid() != null && Objects.equals(getUuid(), that.getUuid());
    }

    @Override
    public final int hashCode() {
        return this instanceof HibernateProxy ? ((HibernateProxy) this).getHibernateLazyInitializer().getPersistentClass().hashCode() : getClass().hashCode();
    }
}
