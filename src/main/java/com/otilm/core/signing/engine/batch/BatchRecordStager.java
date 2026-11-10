package com.otilm.core.signing.engine.batch;

import com.otilm.api.model.client.signing.profile.record.SigningRecordPersistenceMode;
import com.otilm.core.model.signing.SigningProfileModel;
import com.otilm.core.signing.engine.error.SigningEngineException;
import com.otilm.core.signing.engine.error.SigningEngineFailure;
import com.otilm.core.signing.record.SigningRecordInputSource;
import com.otilm.core.signing.record.SigningRecordStrategyFactory;
import java.util.List;
import java.util.UUID;
import org.springframework.stereotype.Component;

/**
 * Stages signing records for a batch run. The records are stored in the order of the items in the request.
 */
@Component
public class BatchRecordStager {

    private static final String STEP = "stageSigningRecords";
    private static final String CLIENT_MESSAGE = "Internal error while storing the signing records";

    private final SigningRecordStrategyFactory strategyFactory;

    public BatchRecordStager(SigningRecordStrategyFactory strategyFactory) {
        this.strategyFactory = strategyFactory;
    }

    /**
     * Stages one record per item at the durability of the profile's persistence mode. A staging failure fails the run
     * at the {@code stageSigningRecords} step.
     *
     * @param signingProfile the run's signing profile
     * @param sources one per item in request order
     * @return the UUIDs of the records in source order, or an empty list when the profile records nothing
     */
    public List<UUID> stage(SigningProfileModel<?, ?> signingProfile, List<SigningRecordInputSource> sources)
            throws SigningEngineException {
        SigningRecordPersistenceMode mode = signingProfile.recordPolicy().persistenceMode();
        try {
            return strategyFactory.strategyFor(mode).recordSigning(signingProfile, sources);
        } catch (RuntimeException e) {
            throw SigningEngineException
                    .stepFailed(SigningEngineFailure.STEP_FAILED, STEP, "the signing records could not be staged", e,
                            CLIENT_MESSAGE);
        }
    }
}
