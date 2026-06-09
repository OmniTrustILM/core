package com.otilm.core.dao.repository;

import com.otilm.core.dao.entity.ScheduledJob;
import org.springframework.stereotype.Repository;

import java.util.Optional;
import java.util.UUID;

@Repository
public interface ScheduledJobsRepository extends SecurityFilterRepository<ScheduledJob, UUID> {
    Optional<ScheduledJob> findByJobName(String jobName);
}
