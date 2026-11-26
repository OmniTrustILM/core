package com.otilm.core.service.handler.discovery;

import com.otilm.api.model.client.discovery.DiscoveryWindowMode;
import com.otilm.api.model.scheduler.SchedulerJobExecutionStatus;
import com.otilm.core.dao.repository.ScheduledJobHistoryRepository;
import com.otilm.core.tasks.ScheduledJobInfo;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.OffsetDateTime;
import java.time.ZoneOffset;
import java.util.Optional;
import java.util.UUID;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

/** Works out the instant from which a discovery should look for changes; empty means a full discovery. */
@Component
public class DiscoveryWindowResolver {

    /** Stands in for a run that is not recorded, so that the query excludes no row. */
    private static final UUID NO_EXCLUDED_RUN = new UUID(0, 0);

    private final ScheduledJobHistoryRepository historyRepository;
    private final Clock clock;

    @Autowired
    public DiscoveryWindowResolver(ScheduledJobHistoryRepository historyRepository) {
        this(historyRepository, Clock.systemUTC());
    }

    DiscoveryWindowResolver(ScheduledJobHistoryRepository historyRepository, Clock clock) {
        this.historyRepository = historyRepository;
        this.clock = clock;
    }

    public Optional<OffsetDateTime> resolve(DiscoveryWindowMode mode, Duration lookback, ScheduledJobInfo jobInfo) {
        if (mode == null) {
            return Optional.empty();
        }
        return switch (mode) {
            case FULL -> Optional.empty();
            case LOOKBACK -> Optional.ofNullable(lookback).flatMap(this::lookbackStart);
            case SINCE_LAST_SUCCESSFUL_RUN -> lastSuccessfulRun(jobInfo);
        };
    }

    /** A lookback reaching back before the epoch covers everything, so it runs full instead of overflowing. */
    private Optional<OffsetDateTime> lookbackStart(Duration lookback) {
        OffsetDateTime now = OffsetDateTime.now(clock);
        if (lookback.compareTo(Duration.between(Instant.EPOCH, now.toInstant())) >= 0) {
            return Optional.empty();
        }
        return Optional.of(now.minus(lookback));
    }

    /**
     * A run that ended WARNING counts: the scheduler records it as SUCCESS, so what it missed waits for a full run.
     */
    private Optional<OffsetDateTime> lastSuccessfulRun(ScheduledJobInfo jobInfo) {
        if (jobInfo == null || jobInfo.jobUuid() == null) {
            return Optional.empty();
        }
        UUID currentRun = jobInfo.jobHistoryUuid() != null ? jobInfo.jobHistoryUuid() : NO_EXCLUDED_RUN;
        return historyRepository
                .findFirstByScheduledJobUuidAndSchedulerExecutionStatusAndUuidNotOrderByJobExecutionDesc(
                        jobInfo.jobUuid(), SchedulerJobExecutionStatus.SUCCESS, currentRun)
                .map(run -> run.getJobExecution().toInstant().atOffset(ZoneOffset.UTC));
    }
}
