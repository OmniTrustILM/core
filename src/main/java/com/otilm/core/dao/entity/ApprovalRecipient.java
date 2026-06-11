package com.otilm.core.dao.entity;

import com.otilm.api.model.client.approval.ApprovalStatusEnum;
import com.otilm.api.model.client.approval.ApprovalStepRecipientDto;
import jakarta.persistence.*;
import lombok.*;
import org.hibernate.proxy.HibernateProxy;

import java.util.Date;
import java.util.Objects;
import java.util.UUID;

@Getter
@Setter
@ToString
@RequiredArgsConstructor
@Entity
@Table(name = "approval_recipient")
public class ApprovalRecipient extends UniquelyIdentified {

    @Column(name = "user_uuid")
    private UUID userUuid;

    @Column(name = "approval_step_uuid")
    private UUID approvalStepUuid;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "approval_step_uuid", insertable = false, updatable = false)
    @ToString.Exclude
    private ApprovalStep approvalStep;

    @Column(name = "approval_uuid")
    private UUID approvalUuid;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "approval_uuid", insertable = false, updatable = false)
    @ToString.Exclude
    private Approval approval;

    @Column(name = "status")
    @Enumerated(EnumType.STRING)
    private ApprovalStatusEnum status;

    @Column(name = "comment")
    private String comment;

    @Column(name = "created_at")
    private Date createdAt;

    @Column(name = "closed_at")
    private Date closedAt;

    public ApprovalStepRecipientDto mapToDto() {
        final ApprovalStepRecipientDto dto = new ApprovalStepRecipientDto();
        dto.setApprovalRecipientUuid(this.uuid.toString());
        dto.setComment(this.comment);
        dto.setStatus(this.status);
        dto.setUserUuid(this.userUuid == null ? null : this.userUuid.toString());
        dto.setCreatedAt(this.createdAt);
        dto.setClosedAt(this.closedAt);
        return dto;
    }

    @Override
    public final boolean equals(Object o) {
        if (this == o) return true;
        if (o == null) return false;
        Class<?> oEffectiveClass = o instanceof HibernateProxy ? ((HibernateProxy) o).getHibernateLazyInitializer().getPersistentClass() : o.getClass();
        Class<?> thisEffectiveClass = this instanceof HibernateProxy ? ((HibernateProxy) this).getHibernateLazyInitializer().getPersistentClass() : this.getClass();
        if (thisEffectiveClass != oEffectiveClass) return false;
        ApprovalRecipient that = (ApprovalRecipient) o;
        return getUuid() != null && Objects.equals(getUuid(), that.getUuid());
    }

    @Override
    public final int hashCode() {
        return this instanceof HibernateProxy ? ((HibernateProxy) this).getHibernateLazyInitializer().getPersistentClass().hashCode() : getClass().hashCode();
    }
}
