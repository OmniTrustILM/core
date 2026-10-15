package com.otilm.core.dao.repository;

import com.otilm.api.model.core.compliance.ComplianceStatus;
import com.otilm.core.dao.entity.ComplianceSubject;
import com.otilm.core.model.compliance.ComplianceResultDto;
import java.util.UUID;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.NoRepositoryBean;
import org.springframework.data.repository.query.Param;

/** A repository of subjects a compliance check stores its result on. */
@NoRepositoryBean
public interface ComplianceSubjectRepository<T extends ComplianceSubject> extends SecurityFilterRepository<T, UUID> {

    /**
     * Stores a compliance result on the subject, and the time of the change, and writes nothing else of it.
     *
     * @return the number of subjects updated
     */
    @Modifying
    @Query("UPDATE #{#entityName} s SET s.complianceStatus = :status, s.complianceResult = :result,"
            + " s.updated = CURRENT_TIMESTAMP WHERE s.uuid = :uuid")
    int updateComplianceResult(@Param("uuid") UUID uuid, @Param("status") ComplianceStatus status,
            @Param("result") ComplianceResultDto result);
}
