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
 * The strategy's job is narrow: every call ticks the intake funnel on the shared ancestor; an empty policy is
 * skipped, otherwise it maps + persists synchronously and counts the persist stage. Unlike the best-effort
 * strategy it has no queue and does not swallow persistence failures — they propagate to the caller, and the
 * failure ticks both the stage-2 {@code persist.failed} and the stage-1 {@code intake.failed{persist_error}}.
 * Persistence wiring (mapper output, columns, transaction) is covered against the real context in
 * {@link ImmediateSigningRecordStrategyTest}.
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
    void record_countsIntakeSkippedAndDoesNotPersist_whenPolicyRecordsNothing() {
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
        assertEquals(1, intakeCounter(MODE));
        assertEquals(1, intakeSkippedCounter(MODE));
        assertEquals(0, persistCounter(MODE));
        verifyNoInteractions(writer);
    }

    @Test
    void record_insertsMappedRecordAndCountsPersist_whenPolicyRecordsContent() {
        // given
        var recordableInput = recordableInput();

        // when
        strategy.record(recordableInput);

        // then
        verify(writer).insert(any(SigningRecord.class));
        assertEquals(1, intakeCounter(MODE));
        assertEquals(1, persistCounter(MODE));
        assertEquals(0, persistFailedCounter(MODE));
        assertEquals(1, durationSampleCount(MODE));
    }

    @Test
    void record_propagatesAndCountsPersistFailedAndIntakeFailed_whenInsertFails() {
        // given
        doThrow(new RuntimeException("db down")).when(writer).insert(any());

        // when
        Executable record = () -> strategy.record(recordableInput());

        // then
        assertThrows(RuntimeException.class, record);
        assertEquals(1, persistCounter(MODE)); // attempt is counted before the insert
        assertEquals(1, persistFailedCounter(MODE));
        assertEquals(1, intakeFailedCounter(MODE, SigningRecordMetrics.REASON_PERSIST_ERROR));
    }

    private SigningRecordInput recordableInput() {
        return aSigningRecordInput()
                .signingProfile(aSigningProfile().recordPolicy(recordingEverything().build()).build())
                .build();
    }

    private double intakeCounter(String mode) {
        var counter = registry.find("signing_record.intake").tag("mode", mode).counter();
        return counter == null ? 0d : counter.count();
    }

    private double intakeSkippedCounter(String mode) {
        var counter = registry.find("signing_record.intake.skipped").tag("mode", mode).counter();
        return counter == null ? 0d : counter.count();
    }

    private double intakeFailedCounter(String mode, String reason) {
        var counter = registry.find("signing_record.intake.failed").tag("mode", mode).tag("reason", reason).counter();
        return counter == null ? 0d : counter.count();
    }

    private double persistCounter(String mode) {
        var counter = registry.find("signing_record.persist").tag("mode", mode).counter();
        return counter == null ? 0d : counter.count();
    }

    private double persistFailedCounter(String mode) {
        var counter = registry.find("signing_record.persist.failed").tag("mode", mode).counter();
        return counter == null ? 0d : counter.count();
    }

    private long durationSampleCount(String mode) {
        Timer timer = registry.find("signing_record.write.duration").tag("mode", mode).timer();
        return timer == null ? 0L : timer.count();
    }
}
