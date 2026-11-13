package com.otilm.core.signing.engine.batch;

import com.otilm.api.model.client.signing.profile.record.SigningRecordPersistenceMode;
import com.otilm.core.model.signing.SigningProfileModel;
import com.otilm.core.signing.engine.error.SigningEngineException;
import com.otilm.core.signing.engine.error.SigningEngineFailure;
import com.otilm.core.signing.record.SigningRecordInputSource;
import com.otilm.core.signing.record.SigningRecordStrategyFactory;
import java.util.List;
import java.util.UUID;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

/**
 * Stages signing records for a batch run. The records are stored in the order of the items in the request.
 */
@Component
public class BatchRecordStager {

    private static final Logger logger = LoggerFactory.getLogger(BatchRecordStager.class);
    private static final String STEP = "stageSigningRecords";
    private static final String CLIENT_MESSAGE = "Internal error while storing the signing records";

    private final SigningRecordStrategyFactory strategyFactory;

    public BatchRecordStager(SigningRecordStrategyFactory strategyFactory) {
        this.strategyFactory = strategyFactory;
    }

    /**
     * Stages one record per item at the durability of the profile's persistence mode. A staging failure under a durable
     * mode fails the run at the {@code stageSigningRecords} step; under {@code BEST_EFFORT}, whose records may be lost,
     * it leaves the run without record references.
     *
     * @param signingProfile the run's signing profile
     * @param sources one per item in request order
     * @return the UUIDs of the records in source order, or an empty list when the profile records nothing or its
     * best-effort records could not be staged
     */
    public List<UUID> stage(SigningProfileModel<?, ?> signingProfile, List<SigningRecordInputSource> sources)
            throws SigningEngineException {
        SigningRecordPersistenceMode mode = signingProfile.recordPolicy().persistenceMode();
        try {
            return strategyFactory.strategyFor(mode).recordSigning(signingProfile, sources);
        } catch (RuntimeException e) {
            if (mode == SigningRecordPersistenceMode.BEST_EFFORT) {
                logger
                        .error("Lost {} best-effort signing record(s) of signing profile '{}' while staging them",
                                sources.size(), signingProfile.name(), e);
                return List.of();
            }
            throw SigningEngineException
                    .stepFailed(SigningEngineFailure.STEP_FAILED, STEP, "the signing records could not be staged", e,
                            CLIENT_MESSAGE);
        }
    }
}
