package com.czertainly.core.dao.entity;

import com.otilm.api.model.common.enums.IPlatformEnum;
import com.otilm.api.model.core.compliance.ComplianceStatus;
import com.czertainly.core.model.compliance.ComplianceResultDto;

public interface ComplianceSubject extends UniquelyIdentifiedObject {

    IPlatformEnum getType();

    IPlatformEnum getFormat();

    String getContentData();

    ComplianceStatus getComplianceStatus();

    void setComplianceStatus(ComplianceStatus complianceStatus);

    ComplianceResultDto getComplianceResult();

    void setComplianceResult(ComplianceResultDto complianceResultDto);
}
