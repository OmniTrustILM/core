package com.otilm.core.dao.repository;

import com.otilm.core.dao.entity.Certificate;
import com.otilm.core.dao.entity.CertificateEventHistory;
import java.util.List;
import org.springframework.stereotype.Repository;

@Repository
public interface CertificateEventHistoryRepository extends SecurityFilterRepository<CertificateEventHistory, Long> {
    List<CertificateEventHistory> findByCertificateOrderByCreatedDesc(Certificate certificate);
}
