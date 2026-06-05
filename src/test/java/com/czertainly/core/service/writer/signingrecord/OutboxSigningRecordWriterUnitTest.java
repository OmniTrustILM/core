package com.czertainly.core.service.writer.signingrecord;

import com.czertainly.core.dao.entity.signing.SigningRecordOutbox;
import com.czertainly.core.dao.repository.signing.SigningRecordOutboxRepository;
import com.czertainly.core.dao.repository.signing.SigningRecordRepository;
import com.czertainly.core.mapper.signing.SigningRecordInputMapper;
import com.czertainly.core.signing.record.SigningRecordInput;
import com.czertainly.core.signing.record.SigningRecordMetrics;
import io.micrometer.core.instrument.MeterRegistry;
import io.micrometer.core.instrument.Timer;
import io.micrometer.core.instrument.simple.SimpleMeterRegistry;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.function.Executable;

import static com.czertainly.core.model.signing.SigningProfileModelBuilder.aSigningProfile;
import static com.czertainly.core.model.signing.SigningRecordPolicyModelBuilder.notRecording;
import static com.czertainly.core.model.signing.SigningRecordPolicyModelBuilder.recordingEverything;
import static com.czertainly.core.signing.record.SigningRecordInputBuilder.aSigningRecordInput;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;

/**
 * Pure unit test for {@link OutboxSigningRecordWriter} over a mocked {@link SigningRecordOutboxRepository}.
 * The writer's job is narrow: skip empty policies, otherwise map + stage into the outbox + count synchronously.
 * Like the immediate writer (and unlike the best-effort writer) it does not swallow persistence failures — they
 * propagate to the caller. What distinguishes it is the {@code DEFERRED_DURABLE} mode and the extra
 * {@code outbox.enqueued} counter, asserted here. Persistence wiring (the row landing in {@code signing_record_outbox}
 * and not {@code signing_record}, field fidelity through jsonb/byte[] columns) is covered against the real context in
 * {@link OutboxSigningRecordWriterTest}.
 */
class OutboxSigningRecordWriterUnitTest {

    private static final String MODE = "DEFERRED_DURABLE";

    private MeterRegistry registry;
    private SigningRecordOutboxRepository repository;
    private OutboxSigningRecordWriter writer;

    @BeforeEach
    void setUp() {
        registry = new SimpleMeterRegistry();
        repository = mock(SigningRecordOutboxRepository.class);
        writer = new OutboxSigningRecordWriter(repository, mock(SigningRecordRepository.class),
                new SigningRecordInputMapper(), new SigningRecordMetrics(registry));
    }

    @Test
    void record_skipsAndCounts_whenPolicyRecordsNothing() {
        // given
        var notRecordingInput = aSigningRecordInput()
                .signingProfile(
                        aSigningProfile()
                                .recordPolicy(
                                        notRecording()
                                                .build())
                                .build())
                .build();

        // when
        writer.record(notRecordingInput);

        // then
        assertEquals(1, skippedCounter());
        verifyNoInteractions(repository);
        assertEquals(0, createdCounter(MODE));
        assertEquals(0, outboxEnqueuedCounter());
    }

    @Test
    void record_stagesMappedOutboxRowAndCountsCreatedAndEnqueued_whenPolicyRecordsContent() {
        // given
        var recordableInput = recordableInput();

        // when
        writer.record(recordableInput);

        // then
        verify(repository).saveAndFlush(any(SigningRecordOutbox.class));
        assertEquals(1, createdCounter(MODE));
        assertEquals(1, outboxEnqueuedCounter());
        assertEquals(1, durationSampleCount(MODE));
    }

    @Test
    void record_propagatesFailureCountsPersistFailedAndDoesNotCountCreatedOrEnqueued_whenSaveFails() {
        // given
        doThrow(new RuntimeException("db down")).when(repository).saveAndFlush(any());

        // when
        Executable record = () -> writer.record(recordableInput());

        // then
        assertThrows(RuntimeException.class, record);
        assertEquals(1, persistFailedCounter(MODE));
        assertEquals(0, createdCounter(MODE));
        assertEquals(0, outboxEnqueuedCounter());
    }

    private SigningRecordInput recordableInput() {
        return aSigningRecordInput()
                .signingProfile(aSigningProfile().recordPolicy(recordingEverything().build()).build())
                .build();
    }

    private double skippedCounter() {
        return registry.get("signing_record.skipped_no_content_policy.total").counter().count();
    }

    private double createdCounter(String mode) {
        var counter = registry.find("signing_record.created.total").tag("mode", mode).counter();
        return counter == null ? 0d : counter.count();
    }

    private double outboxEnqueuedCounter() {
        var counter = registry.find("signing_record.outbox.enqueued.total").counter();
        return counter == null ? 0d : counter.count();
    }

    private double persistFailedCounter(String mode) {
        var counter = registry.find("signing_record.persist.failed.total").tag("mode", mode).counter();
        return counter == null ? 0d : counter.count();
    }

    private long durationSampleCount(String mode) {
        Timer timer = registry.find("signing_record.write.duration_ms").tag("mode", mode).timer();
        return timer == null ? 0L : timer.count();
    }
}
