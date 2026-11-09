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
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
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

    private static final SigningRecordPersistenceMode PROFILE_MODE = SigningRecordPersistenceMode.IMMEDIATE;
    private static final SigningProfileModel<?, ?> RECORDING_PROFILE = aSigningProfile()
            .withRecordPolicy(recordingEverything().persistenceMode(PROFILE_MODE).build())
            .build();

    @Mock
    private SigningRecordStrategyFactory strategyFactory;

    @Mock
    private SigningRecordStrategy strategy;

    @InjectMocks
    private BatchRecordStager stager;

    private List<SigningRecordInputSource> batch;

    @BeforeEach
    void stubTheProfileStrategy() {
        batch = List.of(recordableSource(), recordableSource());
        when(strategyFactory.strategyFor(PROFILE_MODE)).thenReturn(strategy);
    }

    @Test
    void returnsTheRecordReferences_whenStagingSucceeds() throws Exception {
        // given
        List<UUID> recordUuids = List.of(UUID.randomUUID(), UUID.randomUUID());
        when(strategy.record(RECORDING_PROFILE, batch)).thenReturn(recordUuids);

        // when
        List<UUID> references = stager.stage(RECORDING_PROFILE, batch);

        // then
        assertThat(references).isEqualTo(recordUuids);
    }

    @Test
    void failsTheRunAtTheStagingStep_whenStagingFails() {
        // given
        var stagingFailure = new IllegalStateException("outbox insert violated a constraint");
        when(strategy.record(RECORDING_PROFILE, batch)).thenThrow(stagingFailure);

        // when
        ThrowingCallable stage = () -> stager.stage(RECORDING_PROFILE, batch);

        // then
        assertThatThrownBy(stage).isInstanceOfSatisfying(SigningEngineException.class, failure -> {
            assertThat(failure.failure()).isEqualTo(SigningEngineFailure.STEP_FAILED);
            assertThat(failure.step()).isEqualTo("stageSigningRecords");
            assertThat(failure.getCause()).isSameAs(stagingFailure);
            assertThat(failure.clientMessage()).doesNotContain(stagingFailure.getMessage());
        });
    }

    // ── Helpers ───────────────────────────────────────────────────────────────

    private static SigningRecordInputSource recordableSource() {
        return SigningRecordInputSources.of(aSigningRecordInput().signingProfile(RECORDING_PROFILE).build());
    }
}
