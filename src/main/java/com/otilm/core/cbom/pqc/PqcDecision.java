package com.otilm.core.cbom.pqc;

import com.otilm.api.model.core.cryptoasset.PqcVerdict;
import java.util.Map;

/**
 * What the rule set concluded about one asset.
 *
 * @param evaluatedFields the deciding rule's declared inputs. Served verbatim to clients; see {@link PqcRuleInput}
 */
public record PqcDecision(PqcVerdict verdict, String ruleId, String reason, Map<String, Object> evaluatedFields) {

    public PqcDecision {
        evaluatedFields = Map.copyOf(evaluatedFields);
    }
}
