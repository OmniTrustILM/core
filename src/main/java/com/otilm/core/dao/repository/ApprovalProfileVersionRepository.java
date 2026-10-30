package com.otilm.core.dao.repository;

import com.otilm.core.dao.entity.ApprovalProfileVersion;
import java.util.UUID;
import org.springframework.stereotype.Repository;

@Repository
public interface ApprovalProfileVersionRepository extends SecurityFilterRepository<ApprovalProfileVersion, UUID> {
}
