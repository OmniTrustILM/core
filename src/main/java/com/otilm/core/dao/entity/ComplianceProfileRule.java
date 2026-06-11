package com.otilm.core.dao.entity;

import com.otilm.api.model.client.attribute.RequestAttribute;
import com.otilm.api.model.core.auth.Resource;
import com.otilm.api.model.core.compliance.ComplianceRuleAvailabilityStatus;
import com.fasterxml.jackson.annotation.JsonBackReference;
import jakarta.persistence.*;
import lombok.*;
import org.hibernate.annotations.JdbcTypeCode;
import org.hibernate.proxy.HibernateProxy;
import org.hibernate.type.SqlTypes;

import java.io.Serializable;
import java.util.List;
import java.util.Objects;
import java.util.UUID;

/**
 * Entity containing the relation between the Compliance Profile and the Rule. This has to be maintained separately
 * considering that each rule can have its own attributes and values. And the values may be different for each compliance
 * profile. This entity frames the relation with the Compliance Profile and the Compliance Rules discovered from the
 * connector. In addition to that, it also stores the attributes needed for the rule
 */
@Getter
@Setter
@ToString
@RequiredArgsConstructor
@Entity
@Table(name = "compliance_profile_rule")
public class ComplianceProfileRule extends UniquelyIdentified implements Serializable {

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "compliance_profile_uuid", nullable = false, insertable = false, updatable = false)
    @ToString.Exclude
    @JsonBackReference
    private ComplianceProfile complianceProfile;

    @Column(name = "compliance_profile_uuid", nullable = false)
    private UUID complianceProfileUuid;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "connector_uuid", insertable = false, updatable = false)
    @ToString.Exclude
    private Connector connector;

    @Column(name = "connector_uuid")
    private UUID connectorUuid;

    @Column(name = "kind")
    private String kind;

    @Column(name = "compliance_rule_uuid")
    private UUID complianceRuleUuid;

    @Column(name = "compliance_group_uuid")
    private UUID complianceGroupUuid;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "internal_rule_uuid", insertable = false, updatable = false)
    @ToString.Exclude
    private ComplianceInternalRule internalRule;

    @Column(name = "internal_rule_uuid")
    private UUID internalRuleUuid;

    @Enumerated(EnumType.STRING)
    @Column(name = "resource")
    private Resource resource;

    @Column(name = "type")
    private String type;

    @Column(name = "attributes", columnDefinition = "jsonb")
    @JdbcTypeCode(SqlTypes.JSON)
    private List<RequestAttribute> attributes;

    @Transient
    private ComplianceRuleAvailabilityStatus availabilityStatus;

    @Override
    public final boolean equals(Object o) {
        if (this == o) return true;
        if (o == null) return false;
        Class<?> oEffectiveClass = o instanceof HibernateProxy proxy ? proxy.getHibernateLazyInitializer().getPersistentClass() : o.getClass();
        Class<?> thisEffectiveClass = this instanceof HibernateProxy proxy ? proxy.getHibernateLazyInitializer().getPersistentClass() : this.getClass();
        if (thisEffectiveClass != oEffectiveClass) return false;
        if (!(o instanceof ComplianceProfileRule that)) return false;
        return getUuid() != null && Objects.equals(getUuid(), that.getUuid());
    }

    @Override
    public final int hashCode() {
        return this instanceof HibernateProxy proxy ? proxy.getHibernateLazyInitializer().getPersistentClass().hashCode() : getClass().hashCode();
    }
}
