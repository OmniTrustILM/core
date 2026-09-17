package com.otilm.core.service.impl;

import com.otilm.api.clients.SchedulerApiClient;
import com.otilm.api.exception.SchedulerException;
import com.otilm.api.model.core.scheduler.ScheduledJobDetailDto;
import com.otilm.core.dao.entity.ScheduledJob;
import com.otilm.core.dao.repository.ScheduledJobsRepository;
import com.otilm.core.messaging.jms.producers.EventProducer;
import com.otilm.core.tasks.CbomReconcileTask;
import java.util.Optional;
import java.util.UUID;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;
import org.springframework.context.ApplicationContext;
import org.springframework.dao.DataIntegrityViolationException;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * What registering a system job does when another node registered it in the same moment.
 *
 * <p>
 * Registration is a read-then-write with no transaction of its own and no cluster lock, so two nodes booting together
 * both read "absent" and both insert. {@code uq_scheduled_job_job_name} is what makes one of them lose; this is what
 * the loser then does with that refusal. Without a Spring context, because the decision is three lines of one private
 * method and a context would only make the refusal harder to arrange.
 */
class SchedulerJobRegistrationRaceTest {

    private static final String JOB_NAME = CbomReconcileTask.NAME;

    private final ScheduledJobsRepository repository = mock(ScheduledJobsRepository.class);

    private final ApplicationContext applicationContext = mock(ApplicationContext.class);

    private SchedulerServiceImpl service;

    @BeforeEach
    void setUp() {
        CbomReconcileTask task = mock(CbomReconcileTask.class);
        when(task.getDefaultJobName()).thenReturn(JOB_NAME);
        when(task.getDefaultCronExpression()).thenReturn("0 30 2 ? * SUN");
        when(task.getJobClassName()).thenReturn("com.otilm.core.tasks.CbomReconcileTask");
        when(task.isSystemJob()).thenReturn(true);
        when(applicationContext.getBean(CbomReconcileTask.class)).thenReturn(task);

        service = new SchedulerServiceImpl();
        service.setApplicationContext(applicationContext);
        service.setScheduledJobsRepository(repository);
        service.setSchedulerApiClient(mock(SchedulerApiClient.class));
        service.setEventProducer(mock(EventProducer.class));
    }

    /**
     * The row the other node wrote is the registration, and the caller asked for the job to be registered -- which it
     * is. Returning the winner's detail is what makes a rolling restart idempotent rather than a boot failure.
     */
    @Test
    void aRegistrationThatLosesTheInsertRaceReturnsTheWinnersRow() throws SchedulerException {
        ScheduledJob winner = existingJob();
        when(repository.findByJobName(JOB_NAME)).thenReturn(Optional.empty(), Optional.of(winner));
        when(repository.save(any(ScheduledJob.class)))
                .thenThrow(new DataIntegrityViolationException(
                        "duplicate key value violates unique constraint \"uq_scheduled_job_job_name\""));

        ScheduledJobDetailDto registered = service.registerScheduledJob(CbomReconcileTask.class);

        assertThat(registered.getUuid()).isEqualTo(winner.getUuid());
        assertThat(registered.getJobName()).isEqualTo(JOB_NAME);
    }

    /**
     * And any other refusal is still a failure: the job is not registered, so the caller must not be told it is. The
     * driver's text stays in the log -- a constraint violation's DETAIL line quotes the failing row.
     */
    @Test
    void aRefusalThatIsNotTheRaceIsNotReportedAsARegistration() {
        when(repository.findByJobName(JOB_NAME)).thenReturn(Optional.empty());
        when(repository.save(any(ScheduledJob.class)))
                .thenThrow(new DataIntegrityViolationException("null value in column \"cron_expression\""));

        assertThatThrownBy(() -> service.registerScheduledJob(CbomReconcileTask.class))
                .isInstanceOf(SchedulerException.class)
                .hasMessageContaining(JOB_NAME)
                .hasMessageNotContaining("cron_expression");
    }

    /** The ordinary path is unchanged: a job already registered is not inserted again. */
    @Test
    void aJobAlreadyRegisteredIsNotInsertedAgain() throws SchedulerException {
        when(repository.findByJobName(JOB_NAME)).thenReturn(Optional.of(existingJob()));

        service.registerScheduledJob(CbomReconcileTask.class);

        verify(repository, Mockito.never()).save(any(ScheduledJob.class));
    }

    private static ScheduledJob existingJob() {
        ScheduledJob job = new ScheduledJob();
        job.setUuid(UUID.randomUUID());
        job.setJobName(JOB_NAME);
        job.setCronExpression("0 30 2 ? * SUN");
        job.setJobClassName("com.otilm.core.tasks.CbomReconcileTask");
        job.setEnabled(true);
        job.setSystem(true);
        return job;
    }
}
