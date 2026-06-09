
package com.czertainly.core.dao.entity;

import com.otilm.api.model.core.auth.Resource;
import com.otilm.api.model.core.compliance.ComplianceRuleAvailabilityStatus;
import com.otilm.api.model.core.compliance.ComplianceRuleStatus;
import com.otilm.api.model.core.compliance.v2.ComplianceCheckRuleDto;
import com.otilm.api.model.core.compliance.v2.ComplianceRuleDto;
import com.otilm.api.model.core.compliance.v2.ComplianceRuleListDto;
import com.czertainly.core.dao.entity.workflows.ConditionItem;
import jakarta.persistence.*;
import lombok.Getter;
import lombok.RequiredArgsConstructor;
import lombok.Setter;
import lombok.ToString;
import org.hibernate.proxy.HibernateProxy;

import java.util.Objects;
import java.util.Set;

@Getter
@Setter
@ToString
@RequiredArgsConstructor
@Entity
@Table(name = "compliance_internal_rule")
public class ComplianceInternalRule extends UniquelyIdentified {

    @Column(name = "name", nullable = false)
    private String name;

    @Column(name = "description")
    private String description;

    @Column(name = "resource", nullable = false)
    @Enumerated(EnumType.STRING)
    private Resource resource;

    @OneToMany(mappedBy = "complianceInternalRule", fetch = FetchType.LAZY, cascade = CascadeType.ALL)
    @ToString.Exclude
    private Set<ConditionItem> conditionItems;

    public ComplianceRuleDto mapToComplianceRuleDto(Resource resource, ComplianceRuleAvailabilityStatus availabilityStatus, String updatedReason) {
        ComplianceRuleDto dto = new ComplianceRuleDto();
        dto.setUuid(uuid);
        dto.setName(name);
        dto.setDescription(description);
        dto.setAvailabilityStatus(availabilityStatus);
        dto.setUpdatedReason(updatedReason);
        dto.setResource(resource);
        if (conditionItems != null) dto.setConditionItems(conditionItems.stream().map(ConditionItem::mapToDto).toList());

        return dto;
    }

    public ComplianceRuleListDto mapToComplianceRuleListDto() {
        ComplianceRuleListDto dto = new ComplianceRuleListDto();
        dto.setUuid(uuid);
        dto.setName(name);
        dto.setDescription(description);
        dto.setResource(resource);
        if (conditionItems != null) dto.setConditionItems(conditionItems.stream().map(ConditionItem::mapToDto).toList());

        return dto;
    }

    public ComplianceCheckRuleDto mapToComplianceCheckRuleDto(ComplianceRuleStatus status) {
        ComplianceCheckRuleDto dto = new ComplianceCheckRuleDto();
        dto.setUuid(uuid);
        dto.setName(name);
        dto.setDescription(description);
        dto.setStatus(status);
        dto.setResource(resource);

        return dto;
    }


    @Override
    public final boolean equals(Object o) {
        if (this == o) return true;
        if (o == null) return false;
        Class<?> oEffectiveClass = o instanceof HibernateProxy proxy ? proxy.getHibernateLazyInitializer().getPersistentClass() : o.getClass();
        Class<?> thisEffectiveClass = this instanceof HibernateProxy proxy ? proxy.getHibernateLazyInitializer().getPersistentClass() : this.getClass();
        if (thisEffectiveClass != oEffectiveClass) return false;
        if (!(o instanceof ComplianceInternalRule that)) return false;
        return getUuid() != null && Objects.equals(getUuid(), that.getUuid());
    }

    @Override
    public final int hashCode() {
        return this instanceof HibernateProxy proxy ? proxy.getHibernateLazyInitializer().getPersistentClass().hashCode() : getClass().hashCode();
    }
}
