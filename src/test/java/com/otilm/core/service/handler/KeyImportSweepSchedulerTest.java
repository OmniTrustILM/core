package com.otilm.core.service.handler;

import com.otilm.core.config.KeyImportProperties;
import java.time.Duration;
import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import org.awaitility.Awaitility;
import org.junit.jupiter.api.Test;
import org.springframework.scheduling.config.ScheduledTaskRegistrar;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.after;
import static org.mockito.Mockito.atLeast;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.timeout;
import static org.mockito.Mockito.verify;

class KeyImportSweepSchedulerTest {

    private final KeyImportSweeper sweeper = mock(KeyImportSweeper.class);
    private final KeyImportSweepScheduler scheduler = new KeyImportSweepScheduler(sweeper,
            new KeyImportProperties(null, null, null, null, Duration.ofSeconds(30), null));

    @Test
    void configureTasks_startsASweepEverySweepInterval() {
        // given
        ScheduledTaskRegistrar registrar = new ScheduledTaskRegistrar();

        // when
        scheduler.configureTasks(registrar);

        // then
        assertThat(registrar.getFixedDelayTaskList()).singleElement().satisfies(task -> {
            assertThat(task.getIntervalDuration()).isEqualTo(Duration.ofSeconds(30));
            task.getRunnable().run();
        });
        verify(sweeper, timeout(5000)).sweep();
    }

    /** A sweep calls connectors, so it runs apart from the scheduler's thread, and one still running is not doubled. */
    @Test
    void startSweep_runsOneSweepAtATimeOffTheSchedulerThread() throws Exception {
        // given
        CountDownLatch sweeping = new CountDownLatch(1);
        CountDownLatch release = new CountDownLatch(1);
        List<Thread> sweepThreads = new CopyOnWriteArrayList<>();
        doAnswer(invocation -> {
            sweepThreads.add(Thread.currentThread());
            sweeping.countDown();
            return release.await(5, TimeUnit.SECONDS);
        }).when(sweeper).sweep();

        // when
        scheduler.startSweep();
        assertThat(sweeping.await(5, TimeUnit.SECONDS)).isTrue();
        scheduler.startSweep();
        release.countDown();

        // then
        verify(sweeper, after(200).times(1)).sweep();
        assertThat(sweepThreads).singleElement().isNotEqualTo(Thread.currentThread());
    }

    /** A sweep that failed or finished leaves the next one free to start. */
    @Test
    void startSweep_startsAgainOnceTheLastSweepEnded() {
        // given
        doThrow(new IllegalStateException("database unavailable")).doNothing().when(sweeper).sweep();

        // when
        scheduler.startSweep();

        // then
        Awaitility.await().atMost(Duration.ofSeconds(5)).untilAsserted(() -> {
            scheduler.startSweep();
            verify(sweeper, atLeast(2)).sweep();
        });
    }
}
