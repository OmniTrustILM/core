package com.czertainly.core.signing.record;

import com.czertainly.core.dao.entity.signing.SigningRecord;
import com.czertainly.core.mapper.signing.SigningRecordInputMapper;
import com.czertainly.core.service.writer.signingrecord.SigningRecordWriter;
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
 * Pure unit test for {@link ImmediateSigningRecordStrategy} over a mocked {@link SigningRecordWriter}.
 * The strategy's job is narrow: skip empty policies, otherwise map + delegate to the writer + count
 * synchronously. Unlike the best-effort strategy it has no queue and does not swallow persistence failures —
 * they propagate to the caller. Persistence wiring (mapper output, columns, transaction) is covered against
 * the real context in {@link ImmediateSigningRecordStrategyTest}.
 */
class ImmediateSigningRecordStrategyUnitTest {

    private static final String MODE = "IMMEDIATE";

    private MeterRegistry registry;
    private SigningRecordWriter writer;
    private ImmediateSigningRecordStrategy strategy;

    @BeforeEach
    void setUp() {
        registry = new SimpleMeterRegistry();
        writer = mock(SigningRecordWriter.class);
        strategy = new ImmediateSigningRecordStrategy(new SigningRecordMetrics(registry), writer, new SigningRecordInputMapper());
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
        strategy.record(notRecordingInput);

        // then
        assertEquals(1, skippedCounter());
        verifyNoInteractions(writer);
    }

    @Test
    void record_insertsMappedRecordAndCountsCreated_whenPolicyRecordsContent() {
        // given
        var recordableInput = recordableInput();

        // when
        strategy.record(recordableInput);

        // then
        verify(writer).insert(any(SigningRecord.class));
        assertEquals(1, createdCounter(MODE));
        assertEquals(1, durationSampleCount(MODE));
    }

    @Test
    void record_propagatesFailureCountsPersistFailedAndDoesNotCountCreated_whenInsertFails() {
        // given
        doThrow(new RuntimeException("db down")).when(writer).insert(any());

        // when
        Executable record = () -> strategy.record(recordableInput());

        // then
        assertThrows(RuntimeException.class, record);
        assertEquals(0, createdCounter(MODE));
        assertEquals(1, persistFailedCounter(MODE));
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
