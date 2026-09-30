package com.otilm.core.cbom.pqc;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.otilm.api.model.core.cryptoasset.PqcExplanationStepOutcome;
import com.otilm.api.model.core.cryptoasset.PqcVerdict;
import com.otilm.core.dao.repository.cbom.CryptoAssetRepository;
import com.otilm.core.model.cbom.PqcStaleVerdictRow;
import com.otilm.core.serialization.ObjectMapperFactory;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;

/**
 * Recomputes one asset's verdict from the row as the sweep would read it, and writes nothing: the sweep keeps owning
 * the stamp, so an explanation can disagree with the stored verdict and says so.
 */
@Slf4j
@Component
public class PqcVerdictExplainer {

    private static final ObjectMapper JSON_COLUMN = ObjectMapperFactory.jsonColumn();

    private final CryptoAssetRepository assetRepository;
    private final PqcEvaluator evaluator;
    private final PqcReferenceReader referenceReader;

    public PqcVerdictExplainer(CryptoAssetRepository assetRepository, PqcEvaluator evaluator,
            PqcReferenceReader referenceReader) {
        this.assetRepository = assetRepository;
        this.evaluator = evaluator;
        this.referenceReader = referenceReader;
    }

    /**
     * @param inputs what the rules read, empty when the evaluation failed before any was derived
     * @param referenceBasis {@link PqcReferences#basis()} as this explanation read it, for comparison with the stored
     * one
     */
    public record Result(PqcExplanation explanation, Map<String, Object> inputs, String referenceBasis) {
    }

    /** @return empty when the row is gone */
    public Optional<Result> explain(UUID assetUuid) {
        List<PqcStaleVerdictRow> rows = assetRepository.verdictRowsByUuids(List.of(assetUuid));
        if (rows.isEmpty()) {
            return Optional.empty();
        }
        PqcStaleVerdictRow row = rows.get(0);
        // Outside the fallback: a database failure is an error to report, not an asset the rules cannot evaluate.
        Map<UUID, List<PqcReferences.Reference>> loaded = referenceReader.load(rows);
        try {
            JsonNode merged = mergedPayload(row);
            Integer level = PqcEvaluator.nistQuantumSecurityLevel(merged);
            PqcRuleInput input = evaluator.fromStoredRow(row.fields(), merged);
            PqcReferences references = PqcReferenceReader.forRow(row, merged, loaded);
            return Optional
                    .of(new Result(evaluator.explain(input, level, references),
                            PqcEvaluator.inputsOf(input, level, references), references.basis()));
        } catch (RuntimeException e) {
            // The uuid, never the identity key: this line reaches an operator's log aggregator.
            log.warn("PQC verdict explanation failed for cryptographic asset {}", assetUuid, e);
            return Optional.of(failed());
        }
    }

    /** The sweep's own stamp for a row the rules threw on, so both surfaces say the same thing about it. */
    private static Result failed() {
        PqcDecision decision = new PqcDecision(PqcVerdict.UNKNOWN, PqcRules.EVALUATION_FAILED,
                PqcRules.EVALUATION_FAILED_REASON, Map.of());
        PqcExplanation.Step step = new PqcExplanation.Step(PqcRules.EVALUATION_FAILED, "Evaluation",
                PqcExplanationStepOutcome.FAILED, decision.verdict(), decision.reason(), Map.of(), null);
        return new Result(new PqcExplanation(decision, List.of(step)), Map.of(), null);
    }

    private static JsonNode mergedPayload(PqcStaleVerdictRow row) {
        if (row.mergedCryptoPropertiesJson() == null) {
            return null;
        }
        try {
            return JSON_COLUMN.readTree(row.mergedCryptoPropertiesJson());
        } catch (JsonProcessingException e) {
            throw new IllegalStateException("The stored merged payload is not readable as JSON", e);
        }
    }
}
