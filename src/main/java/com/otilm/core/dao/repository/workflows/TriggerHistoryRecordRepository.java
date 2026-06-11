package com.otilm.core.dao.repository.workflows;

import com.otilm.core.dao.entity.workflows.TriggerHistoryRecord;
import com.otilm.core.dao.repository.SecurityFilterRepository;
import org.springframework.stereotype.Repository;

import java.util.UUID;

@Repository
public interface TriggerHistoryRecordRepository extends SecurityFilterRepository<TriggerHistoryRecord, UUID> {
}
