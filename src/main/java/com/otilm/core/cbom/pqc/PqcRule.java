package com.otilm.core.cbom.pqc;

import com.otilm.api.model.core.cryptoasset.PqcVerdict;
import java.util.List;
import java.util.function.Predicate;

/**
 * One readiness rule: what it matches, what it concludes, and which input fields it is allowed to record.
 *
 * @param id stable and operator-facing. It reaches the client as {@code CryptographicAssetVerdictDto.ruleId} and is
 * what makes a deferral queryable -- {@code pqc_rule_id EQUALS CERT-DEFERRED-V1} finds every asset waiting on a
 * generation that can resolve a certificate's public key, which the verdict value alone cannot distinguish from a
 * cipher-suite name.
 * @param reason hardcoded English, never a producer string and never a caught exception's message. It reaches the wire
 * on the same DTO, where a runtime message could carry SQL fragments, internal identifiers or upstream error detail.
 * @param readsFields the allowlist for {@code pqc_evaluated_fields}. Declared per rule rather than collected by
 * watching what the predicate touched, so the recorded evidence is a decision someone made rather than an accident of
 * how a lambda was written. {@link PqcRules#EVIDENCE_FIELDS} is the closed set these names come from, and
 * {@code PqcRulesTest} fails the build on a name outside it.
 */
public record PqcRule(String id, Predicate<PqcRuleInput> matches, PqcVerdict verdict, String reason,
        List<String> readsFields) {

    public PqcRule {
        readsFields = List.copyOf(readsFields);
    }
}
