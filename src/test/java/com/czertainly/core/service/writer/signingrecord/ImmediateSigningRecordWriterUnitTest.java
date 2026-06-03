package com.czertainly.core.service.writer.signingrecord;

import com.czertainly.core.dao.entity.signing.SigningRecord;
import com.czertainly.core.dao.repository.signing.SigningRecordRepository;
import com.czertainly.core.signing.record.SigningRecordInput;
import com.czertainly.core.signing.record.SigningRecordMapper;
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
import static org.mockito.Mockito.*;

/**
 * Pure unit test for {@link ImmediateSigningRecordWriter} over a mocked {@link SigningRecordRepository}.
 * The writer's job is narrow: skip empty policies, otherwise map + save + count synchronously. Unlike the
 * best-effort writer it has no queue and does not swallow persistence failures — they propagate to the caller.
 * Persistence wiring (mapper output, columns, transaction) is covered against the real context in
 * {@link ImmediateSigningRecordWriterTest}.
 */
class ImmediateSigningRecordWriterUnitTest {

    private MeterRegistry registry;
    private SigningRecordRepository repository;
    private ImmediateSigningRecordWriter writer;

    @BeforeEach
    void setUp() {
        registry = new SimpleMeterRegistry();
        repository = mock(SigningRecordRepository.class);
        writer = new ImmediateSigningRecordWriter(repository, new SigningRecordMapper(), new SigningRecordMetrics(registry));
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
    }

    @Test
    void record_savesMappedRecordAndCountsCreated_whenPolicyRecordsContent() {
        // given
        var recordableInput = recordableInput();

        // when
        writer.record(recordableInput);

        // then
        verify(repository).save(any(SigningRecord.class));
        assertEquals(1, createdCounter("IMMEDIATE"));
        assertEquals(1, durationSampleCount("IMMEDIATE"));
    }

    @Test
    void record_propagatesFailureCountsPersistFailedAndDoesNotCountCreated_whenSaveFails() {
        // given
        doThrow(new RuntimeException("db down")).when(repository).save(any());

        // when
        Executable record = () -> writer.record(recordableInput());

        // then
        assertThrows(RuntimeException.class, record);
        assertEquals(0, createdCounter("IMMEDIATE"));
        assertEquals(1, persistFailedCounter("IMMEDIATE"));
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

    private double persistFailedCounter(String mode) {
        var counter = registry.find("signing_record.persist.failed.total").tag("mode", mode).counter();
        return counter == null ? 0d : counter.count();
    }

    private long durationSampleCount(String mode) {
        Timer timer = registry.find("signing_record.write.duration_ms").tag("mode", mode).timer();
        return timer == null ? 0L : timer.count();
    }
}
