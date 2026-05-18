package com.czertainly.core.dao.repository.workflows;

import com.czertainly.api.model.core.auth.Resource;
import com.czertainly.api.model.core.other.ResourceEvent;
import com.czertainly.core.dao.entity.workflows.EventHistory;
import com.czertainly.core.dao.repository.SecurityFilterRepository;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;

import java.util.UUID;

public interface EventHistoryRepository extends SecurityFilterRepository<EventHistory, UUID> {

    Page<EventHistory> findByEventAndResourceAndResourceUuidOrderByStartedAtDesc(ResourceEvent event, Resource resource, UUID resourceUuid, Pageable pageable);
}
