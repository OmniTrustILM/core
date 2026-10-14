package com.otilm.core.cbom.pqc;

import com.otilm.api.model.core.cryptoasset.PqcVerdict;
import java.util.Map;
import java.util.UUID;

/**
 * What the rule set concluded about one asset.
 *
 * @param evaluatedFields the deciding rule's declared inputs. Served verbatim to clients; see {@link PqcRuleInput}
 * @param referencedAssetUuid the asset whose own verdict was carried over, when a reference rule decided
 */
public record PqcDecision(PqcVerdict verdict, String ruleId, String reason, Map<String, Object> evaluatedFields,
        UUID referencedAssetUuid) {

    private static final PqcDecision EVALUATION_FAILED = new PqcDecision(PqcVerdict.UNKNOWN, PqcRules.EVALUATION_FAILED,
            PqcRules.EVALUATION_FAILED_REASON, Map.of());

    public PqcDecision {
        evaluatedFields = Map.copyOf(evaluatedFields);
    }

    public PqcDecision(PqcVerdict verdict, String ruleId, String reason, Map<String, Object> evaluatedFields) {
        this(verdict, ruleId, reason, evaluatedFields, null);
    }

    public static PqcDecision evaluationFailed() {
        return EVALUATION_FAILED;
    }
}
