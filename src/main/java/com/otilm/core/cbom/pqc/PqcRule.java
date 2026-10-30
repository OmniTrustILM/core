package com.otilm.core.cbom.pqc;

import com.otilm.api.model.core.cryptoasset.PqcVerdict;
import java.util.List;
import java.util.function.Predicate;

/**
 * One readiness rule.
 *
 * @param id reaches the client, and is what makes a deferral queryable apart from a genuine not-an-algorithm
 * @param reason hardcoded English. It reaches the wire, so never a producer string or an exception message
 * @param readsFields the allowlist for {@code pqc_evaluated_fields}, declared rather than collected by watching what
 * the predicate touched. Names come from {@link PqcRules#EVIDENCE_FIELDS}; the evaluator refuses anything else
 */
public record PqcRule(String id, Predicate<PqcRuleInput> matches, PqcVerdict verdict, String reason,
        List<String> readsFields) {

    public PqcRule {
        readsFields = List.copyOf(readsFields);
    }
}
