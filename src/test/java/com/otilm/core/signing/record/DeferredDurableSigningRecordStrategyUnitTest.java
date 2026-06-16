package com.otilm.core.signing.record;

import com.otilm.core.dao.entity.signing.SigningRecordOutbox;
import com.otilm.core.mapper.signing.SigningRecordInputMapper;
import com.otilm.core.service.writer.signingrecord.SigningRecordWriter;
import io.micrometer.core.instrument.MeterRegistry;
import io.micrometer.core.instrument.Timer;
import io.micrometer.core.instrument.simple.SimpleMeterRegistry;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.function.Executable;

import static com.otilm.core.util.builders.SigningProfileModelBuilder.aSigningProfile;
import static com.otilm.core.model.signing.SigningRecordPolicyModelBuilder.notRecording;
import static com.otilm.core.model.signing.SigningRecordPolicyModelBuilder.recordingDisabled;
import static com.otilm.core.model.signing.SigningRecordPolicyModelBuilder.recordingEverything;
import static com.otilm.core.signing.record.SigningRecordInputBuilder.aSigningRecordInput;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;

/**
 * Pure unit test for {@link DeferredDurableSigningRecordStrategy} over a mocked {@link SigningRecordWriter}.
 * The strategy's job is narrow: every call ticks the intake funnel on the shared ancestor; an empty policy is
 * skipped, otherwise it maps + stages the row into the outbox synchronously. This is intake stage 1 only — the
 * stage-2 persist is the drainer's job, so no {@code persist} meter is touched here. Like the immediate
 * strategy it does not swallow failures: a staging failure ticks {@code intake.failed{save_error}} and
 * propagates. Persistence wiring (the row landing in {@code signing_record_outbox}, field fidelity through
 * jsonb/byte[] columns) is covered against the real context in {@link DeferredDurableSigningRecordStrategyTest}.
 */
class DeferredDurableSigningRecordStrategyUnitTest {

    private static final String MODE = "DEFERRED_DURABLE";

    private MeterRegistry registry;
    private SigningRecordWriter writer;
    private DeferredDurableSigningRecordStrategy strategy;

    @BeforeEach
    void setUp() {
        registry = new SimpleMeterRegistry();
        writer = mock(SigningRecordWriter.class);
        strategy = new DeferredDurableSigningRecordStrategy(new SigningRecordMetrics(registry), writer, new SigningRecordInputMapper());
    }

    @Test
    void record_countsIntakeSkippedAndDoesNotStage_whenRecordingDisabled() {
        // given
        var recordingDisabledInput = aSigningRecordInput()
                .signingProfile(
                        aSigningProfile()
                                .withRecordPolicy(
                                        recordingDisabled()
                                                .build())
                                .build())
                .build();

        // when
        strategy.recordSigning(recordingDisabledInput);

        // then
        assertEquals(1, intakeCounter(MODE));
        assertEquals(1, intakeSkippedCounter(MODE));
        verifyNoInteractions(writer);
    }

    @Test
    void record_stagesMetadataOnlyOutboxRow_whenRecordingEnabledButNoContentSelected() {
        // given
        var metadataOnlyInput = aSigningRecordInput()
                .signingProfile(
                        aSigningProfile()
                                .withRecordPolicy(
                                        notRecording()
                                                .build())
                                .build())
                .build();

        // when
        strategy.recordSigning(metadataOnlyInput);

        // then
        verify(writer).insertOutbox(any(SigningRecordOutbox.class));
        assertEquals(1, intakeCounter(MODE));
        assertEquals(0, intakeSkippedCounter(MODE));
    }

    @Test
    void record_stagesMappedOutboxRowAndCountsIntake_whenPolicyRecordsContent() {
        // given
        var recordableInput = recordableInput();

        // when
        strategy.recordSigning(recordableInput);

        // then
        verify(writer).insertOutbox(any(SigningRecordOutbox.class));
        assertEquals(1, intakeCounter(MODE));
        assertEquals(0, intakeFailedCounter(MODE, SigningRecordMetrics.REASON_SAVE_ERROR));
        assertEquals(1, durationSampleCount(MODE));
    }

    @Test
    void record_propagatesAndCountsIntakeFailed_whenStagingFails() {
        // given
        doThrow(new RuntimeException("db down")).when(writer).insertOutbox(any());

        // when
        Executable signingRecord = () -> strategy.recordSigning(recordableInput());

        // then
        assertThrows(RuntimeException.class, signingRecord);
        assertEquals(1, intakeFailedCounter(MODE, SigningRecordMetrics.REASON_SAVE_ERROR));
    }

    private SigningRecordInput recordableInput() {
        return aSigningRecordInput()
                .signingProfile(aSigningProfile().withRecordPolicy(recordingEverything().build()).build())
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

    private long durationSampleCount(String mode) {
        Timer timer = registry.find("signing_record.write.duration").tag("mode", mode).timer();
        return timer == null ? 0L : timer.count();
    }
}
