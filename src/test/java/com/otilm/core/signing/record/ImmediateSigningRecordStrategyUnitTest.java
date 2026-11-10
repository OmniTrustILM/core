package com.otilm.core.signing.record;

import com.otilm.core.dao.entity.signing.SigningRecord;
import com.otilm.core.mapper.signing.SigningRecordInputMapper;
import com.otilm.core.model.signing.SigningProfileModel;
import com.otilm.core.service.writer.signingrecord.SigningRecordWriter;
import io.micrometer.core.instrument.MeterRegistry;
import io.micrometer.core.instrument.Timer;
import io.micrometer.core.instrument.simple.SimpleMeterRegistry;
import java.util.List;
import java.util.UUID;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.function.Supplier;
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
 * Pure unit test for {@link ImmediateSigningRecordStrategy} over a mocked {@link SigningRecordWriter}. The strategy's
 * job is narrow: every call ticks the intake funnel on the shared ancestor; an empty policy is skipped, otherwise it
 * maps + persists synchronously and counts the persist stage. Unlike the best-effort strategy it has no queue and does
 * not swallow persistence failures — they propagate to the caller, and the failure ticks both the stage-2
 * {@code persist.failed} and the stage-1 {@code intake.failed{persist_error}}. Persistence wiring (mapper output,
 * columns, transaction) is covered against the real context in
 * {@link com.otilm.core.integration.signing.record.ImmediateSigningRecordStrategyITest}.
 */
class ImmediateSigningRecordStrategyUnitTest {

    private static final String MODE = "IMMEDIATE";

    private MeterRegistry registry;
    private SigningRecordWriter writer;
    private ImmediateSigningRecordStrategy strategy;
    private final SigningProfileModel<?, ?> recordingProfile = aSigningProfile()
            .withRecordPolicy(recordingEverything().build())
            .build();

    @BeforeEach
    void setUp() {
        registry = new SimpleMeterRegistry();
        writer = mock(SigningRecordWriter.class);
        strategy = new ImmediateSigningRecordStrategy(new SigningRecordMetrics(registry), writer,
                new SigningRecordInputMapper());
    }

    @Test
    void record_countsIntakeSkippedAndDoesNotPersist_whenRecordingDisabled() {
        // given
        var recordingDisabledInput = aSigningRecordInput()
                .signingProfile(aSigningProfile().withRecordPolicy(recordingDisabled().build()).build())
                .build();

        // when
        recordOne(strategy, recordingDisabledInput);

        // then
        assertEquals(1, intakeCounter(MODE));
        assertEquals(1, intakeSkippedCounter(MODE));
        assertEquals(0, persistCounter(MODE));
        verifyNoInteractions(writer);
    }

    @Test
    void record_insertsMetadataOnlyRecord_whenRecordingEnabledButNoContentSelected() {
        // given
        var metadataOnlyInput = aSigningRecordInput()
                .signingProfile(aSigningProfile().withRecordPolicy(notRecording().build()).build())
                .build();

        // when
        recordOne(strategy, metadataOnlyInput);

        // then
        verify(writer).insertBatch(any());
        assertEquals(1, intakeCounter(MODE));
        assertEquals(0, intakeSkippedCounter(MODE));
        assertEquals(1, persistCounter(MODE));
    }

    @Test
    void record_insertsMappedRecordAndCountsPersist_whenPolicyRecordsContent() {
        // given
        var recordableInput = recordableInput();

        // when
        recordOne(strategy, recordableInput);

        // then
        verify(writer).insertBatch(any());
        assertEquals(1, intakeCounter(MODE));
        assertEquals(1, persistCounter(MODE));
        assertEquals(0, persistFailedCounter(MODE));
        assertEquals(1, countDurationSamples(MODE));
    }

    @Test
    void returnsRecordUuidsInSourceOrder_whenRecordingABatch() {
        // given
        List<String> sourceNames = List.of("first", "second", "third");
        List<SigningRecordInputSource> batch = sourceNames.stream().map(this::createNamedSource).toList();

        // when
        List<UUID> references = strategy.recordSigning(recordingProfile, batch);

        // then
        List<SigningRecord> inserted = captureInsertedBatch();
        assertThat(inserted).extracting(SigningRecord::getName).containsExactlyElementsOf(sourceNames);
        assertThat(references).containsExactlyElementsOf(inserted.stream().map(SigningRecord::getUuid).toList());
    }

    @Test
    void countsEveryItemThroughTheFunnel_whenRecordingABatch() {
        // given
        List<SigningRecordInputSource> batch = createRecordableBatch(3);

        // when
        strategy.recordSigning(recordingProfile, batch);

        // then
        assertThat(intakeCounter(MODE)).isEqualTo(batch.size());
        assertThat(persistCounter(MODE)).isEqualTo(batch.size());
    }

    @Test
    void timesTheBatchAsOneBatchWrite_whenRecordingABatch() {
        // given
        List<SigningRecordInputSource> batch = createRecordableBatch(3);

        // when
        strategy.recordSigning(recordingProfile, batch);

        // then
        assertThat(countBatchDurationSamples(MODE)).isEqualTo(1);
        assertThat(countDurationSamples(MODE)).isZero();
    }

    @Test
    void timesASingleWrite_whenRecordingOneSource() {
        // given
        List<SigningRecordInputSource> oneSource = createRecordableBatch(1);

        // when
        strategy.recordSigning(recordingProfile, oneSource);

        // then
        assertThat(countDurationSamples(MODE)).isEqualTo(1);
        assertThat(countBatchDurationSamples(MODE)).isZero();
    }

    @Test
    void returnsNoReferences_whenTheBatchProfileRecordsNothing() {
        // given
        var recordingDisabledProfile = aSigningProfile().withRecordPolicy(recordingDisabled().build()).build();
        var recordingDisabledInput = aSigningRecordInput().signingProfile(recordingDisabledProfile).build();
        List<SigningRecordInputSource> batch = List
                .of(SigningRecordInputSources.of(recordingDisabledInput),
                        SigningRecordInputSources.of(recordingDisabledInput));

        // when
        List<UUID> references = strategy.recordSigning(recordingDisabledProfile, batch);

        // then
        assertThat(references).isEmpty();
        assertThat(intakeSkippedCounter(MODE)).isEqualTo(batch.size());
        verifyNoInteractions(writer);
    }

    @Test
    void leavesTheSourcesUnbuilt_whenTheBatchProfileRecordsNothing() {
        // given
        var recordingDisabledProfile = aSigningProfile().withRecordPolicy(recordingDisabled().build()).build();
        var builtSources = new AtomicInteger();
        Supplier<SigningRecordInput> countedBuild = () -> {
            builtSources.incrementAndGet();
            return aSigningRecordInput().signingProfile(recordingDisabledProfile).build();
        };
        List<SigningRecordInputSource> batch = List
                .of(new DeferredSigningRecordInputSource(recordingDisabledProfile, countedBuild),
                        new DeferredSigningRecordInputSource(recordingDisabledProfile, countedBuild));

        // when
        strategy.recordSigning(recordingDisabledProfile, batch);

        // then
        assertThat(builtSources).hasValue(0);
    }

    @Test
    void returnsNoReferences_whenTheBatchIsEmpty() {
        // given
        List<SigningRecordInputSource> emptyBatch = List.of();

        // when
        List<UUID> references = strategy.recordSigning(recordingProfile, emptyBatch);

        // then
        assertThat(references).isEmpty();
        verifyNoInteractions(writer);
    }

    @Test
    void failsCountingEveryItem_whenTheBatchWriteFails() {
        // given
        List<SigningRecordInputSource> batch = createRecordableBatch(3);
        doThrow(new RuntimeException("db down")).when(writer).insertBatch(any());

        // when
        ThrowingCallable recordBatch = () -> strategy.recordSigning(recordingProfile, batch);

        // then
        assertThatThrownBy(recordBatch).isInstanceOf(RuntimeException.class).hasMessageContaining("db down");
        assertThat(persistCounter(MODE)).isEqualTo(batch.size());
        assertThat(persistFailedCounter(MODE)).isEqualTo(batch.size());
        assertThat(intakeFailedCounter(MODE, SigningRecordMetrics.REASON_PERSIST_ERROR)).isEqualTo(batch.size());
    }

    @Test
    void rejectsTheBatch_whenASourceRanOnAnotherProfile() {
        // given
        var nextProfileVersion = aSigningProfile()
                .withVersion(recordingProfile.version() + 1)
                .withRecordPolicy(recordingEverything().build())
                .build();
        List<SigningRecordInputSource> batch = List
                .of(SigningRecordInputSources.of(aSigningRecordInput().signingProfile(recordingProfile).build()),
                        SigningRecordInputSources.of(aSigningRecordInput().signingProfile(nextProfileVersion).build()));

        // when
        ThrowingCallable recordBatch = () -> strategy.recordSigning(recordingProfile, batch);

        // then
        assertThatThrownBy(recordBatch).isInstanceOf(IllegalArgumentException.class);
        assertThat(intakeCounter(MODE)).isZero();
        verifyNoInteractions(writer);
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
    private List<SigningRecord> captureInsertedBatch() {
        ArgumentCaptor<List<SigningRecord>> insertedBatch = ArgumentCaptor.forClass(List.class);
        verify(writer).insertBatch(insertedBatch.capture());
        return insertedBatch.getValue();
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

    private long countDurationSamples(String mode) {
        return countWriteDurationSamples(mode, "false");
    }

    private long countBatchDurationSamples(String mode) {
        return countWriteDurationSamples(mode, "true");
    }

    private long countWriteDurationSamples(String mode, String batch) {
        Timer timer = registry.find("signing_record.write.duration").tag("mode", mode).tag("batch", batch).timer();
        return timer == null ? 0L : timer.count();
    }
}
