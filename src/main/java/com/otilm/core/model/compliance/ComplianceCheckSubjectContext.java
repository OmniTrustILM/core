package com.otilm.core.model.compliance;

import com.otilm.core.dao.entity.ComplianceSubject;
import lombok.Getter;
import lombok.Setter;

import java.util.*;

@Getter
public class ComplianceCheckSubjectContext<T extends ComplianceSubject> {

    @Setter
    private boolean isFinalized;

    private final T complianceSubject;
    private final Set<UUID> checkedInternalRules = new HashSet<>();
    private final Map<String, Set<UUID>> checkedProviderRulesMap = new HashMap<>();
    private final Map<String, Set<UUID>> checkedProviderGroupsMap = new HashMap<>();
    private final ComplianceResultDto complianceResult;

    public ComplianceCheckSubjectContext(T complianceSubject, ComplianceResultDto complianceResult) {
        this.complianceSubject = complianceSubject;
        this.complianceResult = complianceResult;
    }
}
