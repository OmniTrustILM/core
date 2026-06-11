package com.otilm.core.dao.repository;

import com.otilm.core.dao.entity.AuditLog;
import org.springframework.stereotype.Repository;

@Repository
public interface AuditLogRepository extends SecurityFilterRepository<AuditLog, Long> {
}
