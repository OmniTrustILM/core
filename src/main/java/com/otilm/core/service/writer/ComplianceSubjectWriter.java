package com.otilm.core.service.writer;

import com.otilm.api.model.core.compliance.ComplianceStatus;
import com.otilm.core.dao.entity.ComplianceSubject;
import com.otilm.core.dao.repository.ComplianceSubjectRepository;
import com.otilm.core.model.compliance.ComplianceResultDto;
import java.util.UUID;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

/** Writer bean for the results of compliance checks, stored on the subjects they checked. */
@Service
public class ComplianceSubjectWriter {

    /**
     * Stores a compliance result on the subject and writes nothing else of it: the check read the subject before its
     * connector calls, and the subject may have changed since.
     *
     * @param repository the repository of the subject's kind
     */
    @Transactional
    public <T extends ComplianceSubject> void storeComplianceResult(ComplianceSubjectRepository<T> repository,
            UUID subjectUuid, ComplianceStatus status, ComplianceResultDto result) {
        repository.updateComplianceResult(subjectUuid, status, result);
    }
}
