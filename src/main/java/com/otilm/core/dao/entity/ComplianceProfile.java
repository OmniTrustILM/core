package com.otilm.core.dao.entity;

import com.otilm.api.model.client.compliance.SimplifiedComplianceProfileDto;
import com.otilm.api.model.common.NameAndUuidDto;
import com.otilm.api.model.core.compliance.ComplianceProviderSummaryDto;
import com.otilm.api.model.core.compliance.v2.*;
import com.otilm.core.util.DtoMapper;
import com.otilm.core.util.ObjectAccessControlMapper;
import jakarta.persistence.*;
import lombok.*;
import org.hibernate.proxy.HibernateProxy;

import java.io.Serializable;
import java.util.*;

/**
 * Compliance Profile entity storing the details of rules and groups associated with the compliance profile.
 * It also holds the manyToMany relation with the RA Profile as they can have more than 1 RA Profile and vice versa
 */
@Getter
@Setter
@ToString
@RequiredArgsConstructor
@Entity
@Table(name = "compliance_profile")
public class ComplianceProfile extends UniquelyIdentifiedAndAudited implements Serializable, DtoMapper<ComplianceProfileDto>, ObjectAccessControlMapper<NameAndUuidDto> {

    @Column(name = "name", nullable = false)
    private String name;

    @Column(name = "description")
    private String description;

    @OneToMany(mappedBy = "complianceProfile", cascade = CascadeType.REMOVE, fetch = FetchType.LAZY)
    @ToString.Exclude
    private Set<ComplianceProfileRule> complianceRules = new HashSet<>();

    @OneToMany(mappedBy = "complianceProfile", fetch = FetchType.LAZY)
    @ToString.Exclude
    private Set<ComplianceProfileAssociation> associations = new HashSet<>();

    public ComplianceProfileListDto mapToListDto() {
        int internalRulesCount = 0;
        int providerRulesCount = 0;
        int providerGroupsCount = 0;
        for (ComplianceProfileRule rule : complianceRules) {
            if (rule.getInternalRuleUuid() != null) {
                ++internalRulesCount;
            } else if (rule.getComplianceRuleUuid() != null) {
                ++providerRulesCount;
            } else {
                ++providerGroupsCount;
            }
        }

        ComplianceProfileListDto complianceProfileDto = new ComplianceProfileListDto();
        complianceProfileDto.setUuid(uuid);
        complianceProfileDto.setName(name);
        complianceProfileDto.setDescription(description);
        complianceProfileDto.setInternalRulesCount(internalRulesCount);
        complianceProfileDto.setProviderRulesCount(providerRulesCount);
        complianceProfileDto.setProviderGroupsCount(providerGroupsCount);
        complianceProfileDto.setAssociations(associations.size());

        return complianceProfileDto;
    }

    @Override
    public ComplianceProfileDto mapToDto() {
        ComplianceProfileDto complianceProfileDto = new ComplianceProfileDto();
        complianceProfileDto.setUuid(uuid);
        complianceProfileDto.setName(name);
        complianceProfileDto.setDescription(description);

        return complianceProfileDto;
    }

    /**
     * MapToDto function concentrating on providing the values that are required only for the List API
     *
     * @return ComplianceProfilesListDto with the response for listing operation
     */
    public com.otilm.api.model.core.compliance.ComplianceProfilesListDto mapToListDtoV1() {
        var complianceProfileDto = new com.otilm.api.model.core.compliance.ComplianceProfilesListDto();
        complianceProfileDto.setName(name);
        complianceProfileDto.setUuid(uuid.toString());
        complianceProfileDto.setDescription(description);

        Map<String, com.otilm.api.model.core.compliance.ComplianceProviderSummaryDto> providersMapping = new TreeMap<>();
        for (ComplianceProfileRule complianceRule : complianceRules) {
            if (complianceRule.getComplianceRuleUuid() != null) {
                String connectorName = complianceRule.getConnector().getName();
                var providerSummary = providersMapping.computeIfAbsent(connectorName, k -> new ComplianceProviderSummaryDto(connectorName));
                providerSummary.setNumberOfRules(providerSummary.getNumberOfRules() + 1);
            } else if (complianceRule.getComplianceGroupUuid() != null) {
                // ??? should we count also rules from groups ???
                String connectorName = complianceRule.getConnector().getName();
                var providerSummary = providersMapping.computeIfAbsent(connectorName, k -> new ComplianceProviderSummaryDto(connectorName));
                providerSummary.setNumberOfGroups(providerSummary.getNumberOfGroups() + 1);
            }
        }

        complianceProfileDto.setRules(providersMapping.values().stream().toList());
        return complianceProfileDto;
    }

    @Override
    public NameAndUuidDto mapToAccessControlObjects() {
        return new NameAndUuidDto(uuid.toString(), name);
    }


    public SimplifiedComplianceProfileDto raProfileMapToDto() {
        SimplifiedComplianceProfileDto complianceProfileDto = new SimplifiedComplianceProfileDto();
        complianceProfileDto.setName(name);
        complianceProfileDto.setDescription(description);
        complianceProfileDto.setUuid(uuid.toString());
        return complianceProfileDto;
    }

    @Override
    public final boolean equals(Object o) {
        if (this == o) return true;
        if (o == null) return false;
        Class<?> oEffectiveClass = o instanceof HibernateProxy proxy ? proxy.getHibernateLazyInitializer().getPersistentClass() : o.getClass();
        Class<?> thisEffectiveClass = this instanceof HibernateProxy proxy ? proxy.getHibernateLazyInitializer().getPersistentClass() : this.getClass();
        if (thisEffectiveClass != oEffectiveClass) return false;
        if (!(o instanceof ComplianceProfile that)) return false;
        return getUuid() != null && Objects.equals(getUuid(), that.getUuid());
    }

    @Override
    public final int hashCode() {
        return this instanceof HibernateProxy proxy ? proxy.getHibernateLazyInitializer().getPersistentClass().hashCode() : getClass().hashCode();
    }
}
