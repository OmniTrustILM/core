package com.otilm.core.cbom.pqc;

import com.otilm.api.model.core.cryptoasset.PqcVerdict;
import java.util.Map;

/**
 * What a rule set concluded about one asset, ready to be persisted by {@code CryptoAssetPqcVerdictWriter}.
 *
 * @param evaluatedFields the values of the deciding rule's declared inputs, projected through
 * {@link PqcRules#EVIDENCE_FIELDS}. Stored as {@code jsonb} and served verbatim to clients, so it holds rule inputs
 * only -- see {@link PqcRuleInput} for why that is a construction rather than a filter.
 */
public record PqcDecision(PqcVerdict verdict, String ruleId, String reason, Map<String, Object> evaluatedFields) {

    public PqcDecision {
        evaluatedFields = Map.copyOf(evaluatedFields);
    }
}
