package com.czertainly.core.dao.repository;

import com.czertainly.core.dao.entity.ComplianceProfileRule;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;
import java.util.UUID;

@Repository
public interface ComplianceProfileRuleRepository extends SecurityFilterRepository<ComplianceProfileRule, Long> {

    Optional<ComplianceProfileRule> findByUuid(UUID uuid);
    Optional<ComplianceProfileRule> findByComplianceProfileUuidAndConnectorUuidAndKindAndComplianceRuleUuid(UUID complianceProfileUuid, UUID connectorUuid, String kind, UUID providerRuleUuid);

    List<ComplianceProfileRule> findByConnectorUuidAndKindAndComplianceRuleUuid(UUID connectorUuid, String kind, UUID providerRuleUuid);

    Optional<ComplianceProfileRule> findByComplianceProfileUuidAndInternalRuleUuid(UUID complianceProfileUuid, UUID internalRuleUuid);

    boolean existsByComplianceProfileUuidAndInternalRuleUuid(UUID complianceProfileUuid, UUID internalRuleUuid);
    boolean existsByComplianceProfileUuidAndConnectorUuidAndKindAndComplianceRuleUuid(UUID complianceProfileUuid, UUID connectorUuid, String kind, UUID providerRuleUuid);
    Optional<ComplianceProfileRule> findByComplianceProfileUuidAndConnectorUuidAndKindAndComplianceGroupUuid(UUID complianceProfileUuid, UUID connectorUuid, String kind, UUID providerGroupUuid);

    boolean existsByComplianceProfileUuidAndConnectorUuidAndKindAndComplianceGroupUuid(UUID complianceProfileUuid, UUID connectorUuid, String kind, UUID providerGroupUuid);

    void deleteByConnectorUuid(UUID connectorUuid);

    void deleteByComplianceProfileUuid(UUID complianceProfileUuid);

    void deleteByComplianceProfileUuidAndInternalRuleUuid(UUID complianceProfileUuid, UUID internalRuleUuid);

    void deleteByComplianceProfileUuidAndConnectorUuidAndKindAndComplianceRuleUuid(UUID complianceProfileUuid, UUID connectorUuid, String kind, UUID providerRuleUuid);

    void deleteByComplianceProfileUuidAndConnectorUuidAndKindAndComplianceGroupUuid(UUID complianceProfileUuid, UUID connectorUuid, String kind, UUID providerGroupUuid);

}
