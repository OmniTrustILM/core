package com.otilm.core.service.handler.discovery;

import com.otilm.api.model.client.discovery.DiscoveryWindowMode;
import com.otilm.api.model.scheduler.SchedulerJobExecutionStatus;
import com.otilm.core.dao.entity.ScheduledJobHistory;
import com.otilm.core.dao.repository.ScheduledJobHistoryRepository;
import com.otilm.core.tasks.ScheduledJobInfo;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.OffsetDateTime;
import java.time.ZoneOffset;
import java.util.Date;
import java.util.Optional;
import java.util.UUID;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class DiscoveryWindowResolverTest {

    private static final Instant NOW = Instant.parse("2026-11-18T12:00:00Z");

    @Mock
    private ScheduledJobHistoryRepository historyRepository;

    private DiscoveryWindowResolver resolver;

    @BeforeEach
    void createResolver() {
        resolver = new DiscoveryWindowResolver(historyRepository, Clock.fixed(NOW, ZoneOffset.UTC));
    }

    @Test
    void resolvesNone_whenModeIsFullOrNull() {
        // given
        var jobInfo = new ScheduledJobInfo("job", UUID.randomUUID(), UUID.randomUUID());

        // when
        Optional<OffsetDateTime> full = resolver.resolve(DiscoveryWindowMode.FULL, Duration.ofDays(1), jobInfo);
        Optional<OffsetDateTime> unset = resolver.resolve(null, Duration.ofDays(1), jobInfo);

        // then
        assertThat(full).isEmpty();
        assertThat(unset).isEmpty();
        verifyNoInteractions(historyRepository);
    }

    @Test
    void resolvesNowMinusLookback() {
        // given
        var lookback = Duration.ofDays(1);

        // when
        Optional<OffsetDateTime> since = resolver.resolve(DiscoveryWindowMode.LOOKBACK, lookback, null);

        // then
        assertThat(since).contains(OffsetDateTime.parse("2026-11-17T12:00:00Z"));
    }

    @Test
    void resolvesNone_whenLookbackReachesBeforeEpoch() {
        // given
        var longerThanSinceTheEpoch = Duration.ofSeconds(Long.MAX_VALUE);

        // when
        Optional<OffsetDateTime> since = resolver.resolve(DiscoveryWindowMode.LOOKBACK, longerThanSinceTheEpoch, null);

        // then
        assertThat(since).isEmpty();
    }

    @Test
    void resolvesLastSuccessfulJobExecution() {
        // given
        var jobInfo = new ScheduledJobInfo("job", UUID.randomUUID(), UUID.randomUUID());
        var lastSuccess = new ScheduledJobHistory();
        lastSuccess.setJobExecution(Date.from(Instant.parse("2026-11-18T10:00:00Z")));
        when(historyRepository
                .findFirstByScheduledJobUuidAndSchedulerExecutionStatusAndUuidNotOrderByJobExecutionDesc(
                        jobInfo.jobUuid(), SchedulerJobExecutionStatus.SUCCESS, jobInfo.jobHistoryUuid()))
                .thenReturn(Optional.of(lastSuccess));

        // when
        Optional<OffsetDateTime> since = resolver.resolve(DiscoveryWindowMode.SINCE_LAST_SUCCESSFUL_RUN, null, jobInfo);

        // then
        assertThat(since).contains(OffsetDateTime.parse("2026-11-18T10:00:00Z"));
    }

    @Test
    void resolvesNone_whenJobHasNoSuccessfulExecution() {
        // given
        var jobInfo = new ScheduledJobInfo("job", UUID.randomUUID(), UUID.randomUUID());
        when(historyRepository
                .findFirstByScheduledJobUuidAndSchedulerExecutionStatusAndUuidNotOrderByJobExecutionDesc(
                        jobInfo.jobUuid(), SchedulerJobExecutionStatus.SUCCESS, jobInfo.jobHistoryUuid()))
                .thenReturn(Optional.empty());

        // when
        Optional<OffsetDateTime> since = resolver.resolve(DiscoveryWindowMode.SINCE_LAST_SUCCESSFUL_RUN, null, jobInfo);

        // then
        assertThat(since).isEmpty();
    }

    @Test
    void resolvesNone_whenSinceLastSuccessfulRunHasNoJob() {
        // given — a discovery started outside a scheduled job
        ScheduledJobInfo noJob = null;

        // when
        Optional<OffsetDateTime> since = resolver.resolve(DiscoveryWindowMode.SINCE_LAST_SUCCESSFUL_RUN, null, noJob);

        // then
        assertThat(since).isEmpty();
        verifyNoInteractions(historyRepository);
    }

    @Test
    void resolvesNone_whenSinceLastSuccessfulRunHasNoJobUuid() {
        // given
        var jobInfo = new ScheduledJobInfo("job");

        // when
        Optional<OffsetDateTime> since = resolver.resolve(DiscoveryWindowMode.SINCE_LAST_SUCCESSFUL_RUN, null, jobInfo);

        // then
        assertThat(since).isEmpty();
        verifyNoInteractions(historyRepository);
    }

    @Test
    void excludesNoRow_whenCurrentExecutionIsUnknown() {
        // given
        var jobUuid = UUID.randomUUID();
        var jobInfo = new ScheduledJobInfo("job", jobUuid, null);
        var lastSuccess = new ScheduledJobHistory();
        lastSuccess.setJobExecution(Date.from(Instant.parse("2026-11-18T10:00:00Z")));
        when(historyRepository
                .findFirstByScheduledJobUuidAndSchedulerExecutionStatusAndUuidNotOrderByJobExecutionDesc(jobUuid,
                        SchedulerJobExecutionStatus.SUCCESS, new UUID(0, 0)))
                .thenReturn(Optional.of(lastSuccess));

        // when
        Optional<OffsetDateTime> since = resolver.resolve(DiscoveryWindowMode.SINCE_LAST_SUCCESSFUL_RUN, null, jobInfo);

        // then
        assertThat(since).contains(OffsetDateTime.parse("2026-11-18T10:00:00Z"));
    }
}
