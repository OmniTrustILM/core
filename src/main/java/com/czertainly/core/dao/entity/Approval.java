package com.czertainly.core.dao.entity;

import com.otilm.api.model.client.approval.ApprovalDetailDto;
import com.otilm.api.model.client.approval.ApprovalDetailStepDto;
import com.otilm.api.model.client.approval.ApprovalDto;
import com.otilm.api.model.client.approval.ApprovalStatusEnum;
import com.otilm.api.model.core.auth.Resource;
import com.czertainly.core.dao.converter.ObjectToJsonConverter;
import com.otilm.core.model.auth.ResourceAction;
import jakarta.persistence.*;
import lombok.*;
import org.hibernate.annotations.JdbcTypeCode;
import org.hibernate.proxy.HibernateProxy;
import org.hibernate.type.SqlTypes;
import org.springframework.data.annotation.CreatedDate;
import org.springframework.data.jpa.domain.support.AuditingEntityListener;

import java.util.*;

@Getter
@Setter
@ToString
@RequiredArgsConstructor
@Entity
@Table(name = "approval")
@EntityListeners(AuditingEntityListener.class)
public class Approval extends UniquelyIdentified {

    @Column(name = "approval_profile_version_uuid")
    private UUID approvalProfileVersionUuid;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "approval_profile_version_uuid", insertable = false, updatable = false)
    @ToString.Exclude
    private ApprovalProfileVersion approvalProfileVersion;

    @Column(name = "creator_uuid")
    private UUID creatorUuid;

    @Column(name = "object_uuid")
    private UUID objectUuid;

    @Column(name = "resource")
    @Enumerated(EnumType.STRING)
    private Resource resource;

    @Column(name = "action")
    @Enumerated(EnumType.STRING)
    private ResourceAction action;

    @Column(name = "status")
    @Enumerated(EnumType.STRING)
    private ApprovalStatusEnum status;

    @CreatedDate
    @Column(name = "created_at")
    private Date createdAt;

    @Column(name = "expiry_at")
    private Date expiryAt;

    @Column(name = "closed_at")
    private Date closedAt;

    @OneToMany(mappedBy = "approval", fetch = FetchType.LAZY)
    @ToString.Exclude
    private List<ApprovalRecipient> approvalRecipients;

    @Column(name = "object_data", columnDefinition = "jsonb")
    @JdbcTypeCode(SqlTypes.JSON)
    @Convert(converter = ObjectToJsonConverter.class)
    private Object objectData;

    public ApprovalDto mapToDto() {
        final ApprovalDto dto = new ApprovalDto();
        dto.setApprovalUuid(this.uuid.toString());
        dto.setCreatorUuid(this.creatorUuid.toString());
        dto.setResource(this.resource);
        dto.setResourceAction(this.action.getCode());
        dto.setVersion(this.getApprovalProfileVersion().getVersion());
        dto.setStatus(this.getStatus());
        dto.setCreatedAt(this.createdAt);
        dto.setClosedAt(this.closedAt);
        dto.setExpiryAt(this.expiryAt);
        dto.setObjectUuid(this.objectUuid.toString());

        final ApprovalProfile approvalProfile = this.getApprovalProfileVersion().getApprovalProfile();
        dto.setApprovalProfileUuid(approvalProfile.getUuid().toString());
        dto.setApprovalProfileName(approvalProfile.getName());

        return dto;
    }

    public ApprovalDetailDto mapToDetailDto() {
        final ApprovalDto approvalDto = mapToDto();
        final ApprovalDetailDto dto = new ApprovalDetailDto(approvalDto);

        dto.setExpiry(this.approvalProfileVersion.getExpiry());
        dto.setDescription(this.approvalProfileVersion.getDescription());

        final List<ApprovalDetailStepDto> approvalStepDtoList = new ArrayList<>();
        if (this.getApprovalRecipients() != null) {
            this.getApprovalRecipients().forEach(recipient -> processRecipient(recipient, approvalStepDtoList));
        }
        dto.setApprovalSteps(approvalStepDtoList);

        return dto;
    }

    private void processRecipient(final ApprovalRecipient recipient, final List<ApprovalDetailStepDto> approvalStepDtos) {
        final Optional<ApprovalDetailStepDto> approvalStepDto = approvalStepDtos.stream().filter(as -> as.getUuid().toString().equals(recipient.getApprovalStepUuid().toString())).findFirst();
        if (approvalStepDto.isPresent()) {
            approvalStepDto.get().getApprovalStepRecipients().add(recipient.mapToDto());
        } else {
            final ApprovalDetailStepDto approvalDetailStepDto = recipient.getApprovalStep().mapToDtoWithExtendedData();
            approvalDetailStepDto.getApprovalStepRecipients().add(recipient.mapToDto());
            approvalStepDtos.add(approvalDetailStepDto);
        }
    }

    @Override
    public final boolean equals(Object o) {
        if (this == o) return true;
        if (o == null) return false;
        Class<?> oEffectiveClass = o instanceof HibernateProxy ? ((HibernateProxy) o).getHibernateLazyInitializer().getPersistentClass() : o.getClass();
        Class<?> thisEffectiveClass = this instanceof HibernateProxy ? ((HibernateProxy) this).getHibernateLazyInitializer().getPersistentClass() : this.getClass();
        if (thisEffectiveClass != oEffectiveClass) return false;
        Approval approval = (Approval) o;
        return getUuid() != null && Objects.equals(getUuid(), approval.getUuid());
    }

    @Override
    public final int hashCode() {
        return this instanceof HibernateProxy ? ((HibernateProxy) this).getHibernateLazyInitializer().getPersistentClass().hashCode() : getClass().hashCode();
    }
}
