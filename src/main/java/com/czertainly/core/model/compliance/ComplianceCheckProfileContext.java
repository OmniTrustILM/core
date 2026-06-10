package com.czertainly.core.model.compliance;

import com.otilm.api.model.core.auth.Resource;
import com.czertainly.core.dao.entity.ComplianceProfileRule;
import com.czertainly.core.dao.entity.ComplianceSubject;
import lombok.Getter;

import java.util.*;

@Getter
public class ComplianceCheckProfileContext {

    private final String name;
    private final Map<Resource, Set<ComplianceSubject>> complianceSubjects;
    private final List<ComplianceProfileRule> internalRules = new ArrayList<>();
    private final Map<String, List<ComplianceProfileRule>> providerRulesMapping = new HashMap<>();

    public ComplianceCheckProfileContext(String name, Map<Resource, Set<ComplianceSubject>> complianceSubjects) {
        this.name = name;
        this.complianceSubjects = complianceSubjects;
    }

    /**
     * Adds a compliance profile rule to the appropriate mapping based on its type.
     *
     * @param providerKey The key identifying the provider of the rule.
     * @param rule        The compliance profile rule to be added.
     */
    public void addProfileRule(String providerKey, ComplianceProfileRule rule) {
        if (rule.getInternalRuleUuid() != null) {
            internalRules.add(rule);
        } else {
            providerRulesMapping.computeIfAbsent(providerKey, k -> new ArrayList<>()).add(rule);
        }
    }

}
