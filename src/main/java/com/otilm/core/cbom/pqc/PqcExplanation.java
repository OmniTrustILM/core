package com.otilm.core.cbom.pqc;

import com.otilm.api.model.core.cryptoasset.PqcExplanationStepOutcome;
import com.otilm.api.model.core.cryptoasset.PqcVerdict;
import java.util.List;
import java.util.Map;
import java.util.UUID;

/**
 * A verdict and the rules walked to reach it. {@code decision} is what {@link PqcEvaluator#evaluate} returns for the
 * same input, by construction.
 */
public record PqcExplanation(PqcDecision decision, List<Step> steps) {

    public PqcExplanation {
        steps = List.copyOf(steps);
    }

    /**
     * @param verdict present on the deciding step only
     * @param evaluatedFields absent on a step that was not reached
     * @param referencedAssetUuid the asset whose verdict a resolved step carried over
     */
    public record Step(String ruleId, String title, PqcExplanationStepOutcome outcome, PqcVerdict verdict,
            String message, Map<String, Object> evaluatedFields, UUID referencedAssetUuid) {
    }
}
