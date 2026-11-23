package com.otilm.core.dao.repository.ai;

import com.otilm.core.dao.entity.ai.AiRuntimeRun;
import com.otilm.core.model.ai.AiRuntimeState.Expected;
import java.time.Instant;
import java.util.Optional;
import java.util.UUID;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.Repository;
import org.springframework.data.repository.query.Param;

/** Local cleanup facts only; terminal/absence proof is the trusted controller's separate responsibility. */
public interface AiRuntimeCleanupRepository extends Repository<AiRuntimeRun, UUID> {
    @Query(value = AiRuntimeCleanupSql.LOCK_ATTEMPT, nativeQuery = true)
    Optional<UUID> lockCurrentAttempt(@Param("e") Expected expected);

    @Query(value = AiRuntimeCleanupSql.LOCK_LAUNCH, nativeQuery = true)
    Optional<UUID> lockLaunch(@Param("attemptId") UUID attemptId);

    @Query(value = AiRuntimeCleanupSql.CURRENT, nativeQuery = true)
    Optional<String> current(@Param("e") Expected expected, @Param("jobUid") String jobUid,
            @Param("workloads") String workloads, @Param("operationDeadline") Instant cutoff);

    @Modifying
    @Query(value = AiRuntimeCleanupSql.COMPLETE, nativeQuery = true)
    int complete(@Param("e") Expected expected, @Param("jobUid") String jobUid, @Param("workloads") String workloads,
            @Param("at") Instant at, @Param("operationDeadline") Instant cutoff);
}
