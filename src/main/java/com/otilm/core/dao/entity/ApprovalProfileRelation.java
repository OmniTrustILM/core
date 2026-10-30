package com.otilm.core.dao.entity;

import com.otilm.api.model.client.approvalprofile.ApprovalProfileRelationDto;
import com.otilm.api.model.core.auth.Resource;
import com.otilm.core.model.auth.ResourceAction;
import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.EnumType;
import jakarta.persistence.Enumerated;
import jakarta.persistence.FetchType;
import jakarta.persistence.JoinColumn;
import jakarta.persistence.ManyToOne;
import jakarta.persistence.Table;
import java.util.Objects;
import java.util.UUID;
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
@Table(name = "approval_profile_relation")
public class ApprovalProfileRelation extends UniquelyIdentified {

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "approval_profile_uuid", insertable = false, updatable = false)
    @ToString.Exclude
    private ApprovalProfile approvalProfile;

    @Column(name = "approval_profile_uuid")
    private UUID approvalProfileUuid;

    @Enumerated(EnumType.STRING)
    @Column(name = "resource")
    private Resource resource;

    @Column(name = "resource_uuid")
    private UUID resourceUuid;

    @Enumerated(EnumType.STRING)
    @Column(name = "action")
    private ResourceAction action;

    public ApprovalProfileRelationDto mapToDto() {
        final ApprovalProfileRelationDto approvalProfileRelationDto = new ApprovalProfileRelationDto();
        approvalProfileRelationDto.setUuid(this.getUuid().toString());
        approvalProfileRelationDto.setApprovalProfileUuid(this.getApprovalProfileUuid().toString());
        approvalProfileRelationDto.setResource(this.getResource());
        approvalProfileRelationDto.setResourceUuid(this.getResourceUuid());
        if (this.action != null) {
            approvalProfileRelationDto.setAction(this.getAction().getCode());
        }

        return approvalProfileRelationDto;
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
        ApprovalProfileRelation that = (ApprovalProfileRelation) o;
        return getUuid() != null && Objects.equals(getUuid(), that.getUuid());
    }

    @Override
    public final int hashCode() {
        return this instanceof HibernateProxy
                ? ((HibernateProxy) this).getHibernateLazyInitializer().getPersistentClass().hashCode()
                : getClass().hashCode();
    }
}
