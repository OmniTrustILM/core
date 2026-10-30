package com.otilm.core.dao.entity;

import com.fasterxml.jackson.annotation.JsonBackReference;
import com.otilm.api.model.client.approvalprofile.ApprovalProfileDetailDto;
import com.otilm.api.model.client.approvalprofile.ApprovalProfileDto;
import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.FetchType;
import jakarta.persistence.JoinColumn;
import jakarta.persistence.ManyToOne;
import jakarta.persistence.OneToMany;
import jakarta.persistence.Table;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;
import java.util.UUID;
import java.util.stream.Collectors;
import lombok.Getter;
import lombok.RequiredArgsConstructor;
import lombok.Setter;
import lombok.ToString;
import org.hibernate.proxy.HibernateProxy;

@Getter
@Setter
@ToString
@RequiredArgsConstructor
@Entity
@Table(name = "approval_profile_version")
public class ApprovalProfileVersion extends UniquelyIdentifiedAndAudited {

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "approval_profile_uuid", insertable = false, updatable = false)
    @ToString.Exclude
    private ApprovalProfile approvalProfile;

    @Column(name = "approval_profile_uuid")
    private UUID approvalProfileUuid;

    @Column(name = "expiry")
    private Integer expiry;

    @Column(name = "description")
    private String description;

    @Column(name = "version")
    private int version = 1;

    @JsonBackReference
    @OneToMany(mappedBy = "approvalProfileVersion", fetch = FetchType.LAZY)
    @ToString.Exclude
    private List<Approval> approvals = new ArrayList<>();

    @OneToMany(mappedBy = "approvalProfileVersion", fetch = FetchType.LAZY)
    @ToString.Exclude
    private List<ApprovalStep> approvalSteps = new ArrayList<>();

    public ApprovalProfileDto mapToDto() {
        final ApprovalProfileDto approvalProfileDto = new ApprovalProfileDto();
        setCommonFields(approvalProfileDto);
        approvalProfileDto.setNumberOfSteps(this.getApprovalSteps().size());
        approvalProfileDto.setAssociations(this.getApprovalProfile().getApprovalProfileRelations().size());
        return approvalProfileDto;
    }

    public ApprovalProfileDetailDto mapToDtoWithSteps() {
        final ApprovalProfileDetailDto approvalProfileDetailDto = new ApprovalProfileDetailDto();
        setCommonFields(approvalProfileDetailDto);
        approvalProfileDetailDto.setAssociations(this.getApprovalProfile().getApprovalProfileRelations().size());

        if (approvalSteps != null) {
            approvalProfileDetailDto
                    .setApprovalSteps(
                            getApprovalSteps().stream().map(ApprovalStep::mapToDto).collect(Collectors.toList()));
        }
        return approvalProfileDetailDto;
    }

    private void setCommonFields(ApprovalProfileDto approvalProfileDto) {
        approvalProfileDto.setUuid(this.getApprovalProfile().getUuid().toString());
        approvalProfileDto.setDescription(this.description);
        approvalProfileDto.setName(this.getApprovalProfile().getName());
        approvalProfileDto.setExpiry(this.expiry);
        approvalProfileDto.setVersion(this.version);
    }

    public ApprovalProfileVersion createNewVersionObject() {
        final ApprovalProfileVersion approvalProfileVersion = new ApprovalProfileVersion();
        approvalProfileVersion.setApprovalProfile(this.approvalProfile);
        approvalProfileVersion.setApprovalProfileUuid(this.approvalProfileUuid);
        approvalProfileVersion.setVersion(this.version + 1);
        approvalProfileVersion.setExpiry(this.expiry);
        approvalProfileVersion.setDescription(this.description);
        approvalProfileVersion.setApprovalSteps(new ArrayList<>());
        return approvalProfileVersion;
    }

    @Override
    public final boolean equals(Object o) {
        if (this == o) {
            return true;
        }
        if (o == null) {
            return false;
        }
        Class<?> oEffectiveClass = o instanceof HibernateProxy
                ? ((HibernateProxy) o).getHibernateLazyInitializer().getPersistentClass()
                : o.getClass();
        Class<?> thisEffectiveClass = this instanceof HibernateProxy
                ? ((HibernateProxy) this).getHibernateLazyInitializer().getPersistentClass()
                : this.getClass();
        if (thisEffectiveClass != oEffectiveClass) {
            return false;
        }
        ApprovalProfileVersion that = (ApprovalProfileVersion) o;
        return getUuid() != null && Objects.equals(getUuid(), that.getUuid());
    }

    @Override
    public final int hashCode() {
        return this instanceof HibernateProxy
                ? ((HibernateProxy) this).getHibernateLazyInitializer().getPersistentClass().hashCode()
                : getClass().hashCode();
    }
}
