package com.otilm.core.signing.engine.batch;

import com.otilm.api.model.client.signing.profile.record.SigningRecordPersistenceMode;
import com.otilm.core.model.signing.SigningProfileModel;
import com.otilm.core.signing.engine.error.SigningEngineException;
import com.otilm.core.signing.engine.error.SigningEngineFailure;
import com.otilm.core.signing.record.SigningRecordInputSource;
import com.otilm.core.signing.record.SigningRecordInputSources;
import com.otilm.core.signing.record.SigningRecordStrategy;
import com.otilm.core.signing.record.SigningRecordStrategyFactory;
import java.util.List;
import java.util.UUID;
import org.assertj.core.api.ThrowableAssert.ThrowingCallable;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import static com.otilm.core.model.signing.SigningRecordPolicyModelBuilder.recordingEverything;
import static com.otilm.core.signing.record.SigningRecordInputBuilder.aSigningRecordInput;
import static com.otilm.core.util.builders.SigningProfileModelBuilder.aSigningProfile;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class BatchRecordStagerTest {

    @Mock
    private SigningRecordStrategyFactory strategyFactory;

    @Mock
    private SigningRecordStrategy strategy;

    @InjectMocks
    private BatchRecordStager stager;

    @Test
    void returnsTheRecordReferences_whenStagingSucceeds() throws Exception {
        // given
        var profile = createRecordingProfile(SigningRecordPersistenceMode.IMMEDIATE);
        var batch = createBatchOf(profile);
        List<UUID> recordUuids = List.of(UUID.randomUUID(), UUID.randomUUID());
        stubTheStrategyOf(profile);
        when(strategy.recordSigning(profile, batch)).thenReturn(recordUuids);

        // when
        List<UUID> references = stager.stage(profile, batch);

        // then
        assertThat(references).isEqualTo(recordUuids);
    }

    @ParameterizedTest
    @EnumSource(names = {"IMMEDIATE", "DEFERRED_DURABLE"})
    void failsTheRunAtTheStagingStep_whenDurableStagingFails(SigningRecordPersistenceMode durableMode) {
        // given
        var profile = createRecordingProfile(durableMode);
        var batch = createBatchOf(profile);
        var stagingFailure = new IllegalStateException("outbox insert violated a constraint");
        stubTheStrategyOf(profile);
        when(strategy.recordSigning(profile, batch)).thenThrow(stagingFailure);

        // when
        ThrowingCallable stage = () -> stager.stage(profile, batch);

        // then
        assertThatThrownBy(stage).isInstanceOfSatisfying(SigningEngineException.class, failure -> {
            assertThat(failure.failure()).isEqualTo(SigningEngineFailure.STEP_FAILED);
            assertThat(failure.step()).isEqualTo("stageSigningRecords");
            assertThat(failure.getCause()).isSameAs(stagingFailure);
            assertThat(failure.clientMessage()).doesNotContain(stagingFailure.getMessage());
        });
    }

    @Test
    void returnsNoReferences_whenBestEffortStagingFails() throws Exception {
        // given
        var bestEffortProfile = createRecordingProfile(SigningRecordPersistenceMode.BEST_EFFORT);
        var batch = createBatchOf(bestEffortProfile);
        stubTheStrategyOf(bestEffortProfile);
        when(strategy.recordSigning(bestEffortProfile, batch))
                .thenThrow(new IllegalStateException("record metadata could not be serialized"));

        // when
        List<UUID> references = stager.stage(bestEffortProfile, batch);

        // then
        assertThat(references).isEmpty();
    }

    // ── Helpers ───────────────────────────────────────────────────────────────

    private void stubTheStrategyOf(SigningProfileModel<?, ?> profile) {
        when(strategyFactory.strategyFor(profile.recordPolicy().persistenceMode())).thenReturn(strategy);
    }

    private static SigningProfileModel<?, ?> createRecordingProfile(SigningRecordPersistenceMode mode) {
        return aSigningProfile().withRecordPolicy(recordingEverything().persistenceMode(mode).build()).build();
    }

    private static List<SigningRecordInputSource> createBatchOf(SigningProfileModel<?, ?> profile) {
        return List.of(createRecordableSource(profile), createRecordableSource(profile));
    }

    private static SigningRecordInputSource createRecordableSource(SigningProfileModel<?, ?> profile) {
        return SigningRecordInputSources.of(aSigningRecordInput().signingProfile(profile).build());
    }
}
