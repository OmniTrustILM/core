package com.otilm.core.signing.record;

import com.otilm.core.dao.entity.signing.SigningRecordOutbox;
import com.otilm.core.mapper.signing.SigningRecordInputMapper;
import com.otilm.core.model.signing.SigningProfileModel;
import com.otilm.core.service.writer.signingrecord.SigningRecordWriter;
import io.micrometer.core.instrument.MeterRegistry;
import io.micrometer.core.instrument.Timer;
import io.micrometer.core.instrument.simple.SimpleMeterRegistry;
import java.util.List;
import java.util.UUID;
import java.util.stream.IntStream;
import org.assertj.core.api.ThrowableAssert.ThrowingCallable;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;

import static com.otilm.core.model.signing.SigningRecordPolicyModelBuilder.notRecording;
import static com.otilm.core.model.signing.SigningRecordPolicyModelBuilder.recordingDisabled;
import static com.otilm.core.model.signing.SigningRecordPolicyModelBuilder.recordingEverything;
import static com.otilm.core.signing.record.SigningRecordInputBuilder.aSigningRecordInput;
import static com.otilm.core.signing.record.SigningRecordInputSources.recordOne;
import static com.otilm.core.util.builders.SigningProfileModelBuilder.aSigningProfile;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;

/**
 * Pure unit test for {@link DeferredDurableSigningRecordStrategy} over a mocked {@link SigningRecordWriter}. The
 * strategy's job is narrow: every call ticks the intake funnel on the shared ancestor; an empty policy is skipped,
 * otherwise it maps + stages the row into the outbox synchronously. This is intake stage 1 only — the stage-2 persist
 * is the drainer's job, so no {@code persist} meter is touched here. Like the immediate strategy it does not swallow
 * failures: a staging failure ticks {@code intake.failed{save_error}} and propagates. Persistence wiring (the row
 * landing in {@code signing_record_outbox}, field fidelity through jsonb/byte[] columns) is covered against the real
 * context in {@link com.otilm.core.integration.signing.record.DeferredDurableSigningRecordStrategyITest}.
 */
class DeferredDurableSigningRecordStrategyUnitTest {

    private static final String MODE = "DEFERRED_DURABLE";

    private MeterRegistry registry;
    private SigningRecordWriter writer;
    private DeferredDurableSigningRecordStrategy strategy;
    private final SigningProfileModel<?, ?> recordingProfile = aSigningProfile()
            .withRecordPolicy(recordingEverything().build())
            .build();

    @BeforeEach
    void setUp() {
        registry = new SimpleMeterRegistry();
        writer = mock(SigningRecordWriter.class);
        strategy = new DeferredDurableSigningRecordStrategy(new SigningRecordMetrics(registry), writer,
                new SigningRecordInputMapper());
    }

    @Test
    void record_countsIntakeSkippedAndDoesNotStage_whenRecordingDisabled() {
        // given
        var recordingDisabledInput = aSigningRecordInput()
                .signingProfile(aSigningProfile().withRecordPolicy(recordingDisabled().build()).build())
                .build();

        // when
        recordOne(strategy, recordingDisabledInput);

        // then
        assertEquals(1, intakeCounter(MODE));
        assertEquals(1, intakeSkippedCounter(MODE));
        verifyNoInteractions(writer);
    }

    @Test
    void record_stagesMetadataOnlyOutboxRow_whenRecordingEnabledButNoContentSelected() {
        // given
        var metadataOnlyInput = aSigningRecordInput()
                .signingProfile(aSigningProfile().withRecordPolicy(notRecording().build()).build())
                .build();

        // when
        recordOne(strategy, metadataOnlyInput);

        // then
        verify(writer).insertOutboxBatch(any());
        assertEquals(1, intakeCounter(MODE));
        assertEquals(0, intakeSkippedCounter(MODE));
    }

    @Test
    void record_stagesMappedOutboxRowAndCountsIntake_whenPolicyRecordsContent() {
        // given
        var recordableInput = recordableInput();

        // when
        recordOne(strategy, recordableInput);

        // then
        verify(writer).insertOutboxBatch(any());
        assertEquals(1, intakeCounter(MODE));
        assertEquals(0, intakeFailedCounter(MODE, SigningRecordMetrics.REASON_SAVE_ERROR));
        assertEquals(1, countDurationSamples(MODE));
    }

    @Test
    void stagesTheBatchInOneWriteReturningUuidsInSourceOrder_whenRecordingABatch() {
        // given
        List<String> sourceNames = List.of("first", "second", "third");
        List<SigningRecordInputSource> batch = sourceNames.stream().map(this::createNamedSource).toList();

        // when
        List<UUID> references = strategy.recordSigning(recordingProfile, batch);

        // then
        List<SigningRecordOutbox> staged = captureStagedBatch();
        assertThat(staged).extracting(SigningRecordOutbox::getName).containsExactlyElementsOf(sourceNames);
        assertThat(references).containsExactlyElementsOf(staged.stream().map(SigningRecordOutbox::getUuid).toList());
        assertThat(intakeCounter(MODE)).isEqualTo(batch.size());
    }

    @Test
    void failsCountingEveryItem_whenStagingTheBatchFails() {
        // given
        List<SigningRecordInputSource> batch = createRecordableBatch(3);
        var stagingFailure = new RuntimeException("db down");
        doThrow(stagingFailure).when(writer).insertOutboxBatch(any());

        // when
        ThrowingCallable recordBatch = () -> strategy.recordSigning(recordingProfile, batch);

        // then
        assertThatThrownBy(recordBatch).isSameAs(stagingFailure);
        assertThat(intakeFailedCounter(MODE, SigningRecordMetrics.REASON_SAVE_ERROR)).isEqualTo(batch.size());
    }

    // ── Helpers ───────────────────────────────────────────────────────────────

    private SigningRecordInput recordableInput() {
        return aSigningRecordInput()
                .signingProfile(aSigningProfile().withRecordPolicy(recordingEverything().build()).build())
                .build();
    }

    private List<SigningRecordInputSource> createRecordableBatch(int size) {
        return IntStream
                .range(0, size)
                .mapToObj(i -> SigningRecordInputSources
                        .of(aSigningRecordInput().signingProfile(recordingProfile).build()))
                .toList();
    }

    private SigningRecordInputSource createNamedSource(String displayName) {
        return SigningRecordInputSources
                .of(aSigningRecordInput().signingProfile(recordingProfile).displayName(displayName).build());
    }

    @SuppressWarnings("unchecked")
    private List<SigningRecordOutbox> captureStagedBatch() {
        ArgumentCaptor<List<SigningRecordOutbox>> stagedBatch = ArgumentCaptor.forClass(List.class);
        verify(writer).insertOutboxBatch(stagedBatch.capture());
        return stagedBatch.getValue();
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

    private long countDurationSamples(String mode) {
        Timer timer = registry.find("signing_record.write.duration").tag("mode", mode).tag("batch", "false").timer();
        return timer == null ? 0L : timer.count();
    }
}
