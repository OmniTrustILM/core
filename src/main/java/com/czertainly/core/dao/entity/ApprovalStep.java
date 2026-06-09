package com.czertainly.core.dao.entity;

import com.otilm.api.model.client.approval.ApprovalDetailStepDto;
import com.otilm.api.model.client.approvalprofile.ApprovalStepDto;
import com.fasterxml.jackson.annotation.JsonBackReference;
import jakarta.persistence.*;
import lombok.*;
import org.hibernate.proxy.HibernateProxy;

import java.util.ArrayList;
import java.util.Objects;
import java.util.UUID;

@Getter
@Setter
@ToString
@RequiredArgsConstructor
@Entity
@Table(name = "approval_step")
public class ApprovalStep extends UniquelyIdentified {

    @Column(name = "approval_profile_version_uuid")
    private UUID approvalProfileVersionUuid;
    
    @ManyToOne(fetch = FetchType.LAZY)
    @JsonBackReference
    @JoinColumn(name = "approval_profile_version_uuid", insertable = false, updatable = false)
    @ToString.Exclude
    private ApprovalProfileVersion approvalProfileVersion;

    @Column(name = "user_uuid")
    private UUID userUuid;

    @Column(name = "role_uuid")
    private UUID roleUuid;

    @Column(name = "group_uuid")
    private UUID groupUuid;

    @Column(name = "description")
    private String description;

    @Column(name = "order_id")
    private int order;

    @Column(name = "required_approvals")
    private int requiredApprovals;

    public ApprovalStepDto mapToDto() {
        final ApprovalStepDto approvalStepDto = new ApprovalStepDto();
        approvalStepDto.setUuid(this.uuid);
        approvalStepDto.setUserUuid(this.userUuid);
        approvalStepDto.setRoleUuid(this.roleUuid);
        approvalStepDto.setGroupUuid(this.groupUuid);
        approvalStepDto.setDescription(this.description);
        approvalStepDto.setOrder(this.order);
        approvalStepDto.setRequiredApprovals(this.requiredApprovals);
        return approvalStepDto;
    }

    public ApprovalDetailStepDto mapToDtoWithExtendedData() {
        final ApprovalStepDto approvalStepDto = mapToDto();
        final ApprovalDetailStepDto dto = new ApprovalDetailStepDto(approvalStepDto);
        dto.setApprovalStepRecipients(new ArrayList<>());
        return dto;
    }

    @Override
    public final boolean equals(Object o) {
        if (this == o) return true;
        if (o == null) return false;
        Class<?> oEffectiveClass = o instanceof HibernateProxy ? ((HibernateProxy) o).getHibernateLazyInitializer().getPersistentClass() : o.getClass();
        Class<?> thisEffectiveClass = this instanceof HibernateProxy ? ((HibernateProxy) this).getHibernateLazyInitializer().getPersistentClass() : this.getClass();
        if (thisEffectiveClass != oEffectiveClass) return false;
        ApprovalStep that = (ApprovalStep) o;
        return getUuid() != null && Objects.equals(getUuid(), that.getUuid());
    }

    @Override
    public final int hashCode() {
        return this instanceof HibernateProxy ? ((HibernateProxy) this).getHibernateLazyInitializer().getPersistentClass().hashCode() : getClass().hashCode();
    }
}
