package com.otilm.core.cbom.pqc;

import com.otilm.api.model.core.cryptoasset.PqcVerdict;
import java.util.Comparator;
import java.util.List;
import java.util.Map;
import java.util.Optional;

/**
 * Which of the rules that matched decides. A total order, so the verdict does not depend on the order the rules were
 * evaluated in:
 *
 * <ol>
 * <li>an {@link PqcRuleCatalog.Tier#EXCLUSION} -- the asset is outside the question, so a salt named {@code DES-salt}
 * is not reported as broken;</li>
 * <li>among {@link PqcRuleCatalog.Tier#FINDING}s the weakest verdict, {@code notReady} before {@code unknown} before
 * {@code ready}, because a weaker rule that also holds is the finding an operator must see;</li>
 * <li>at equal rank the earlier catalogue position;</li>
 * <li>a {@link PqcRuleCatalog.Tier#FALLBACK}, which says only that nothing else could classify the asset.</li>
 * </ol>
 */
final class PqcRuleOrder {

    /** One catalogue entry evaluated against one asset: its decision when the rule's condition held, else why not. */
    record Candidate(PqcRuleCatalog.Entry entry, int position, PqcDecision decision, String notMatched,
            Map<String, Object> evidence) {

        boolean matched() {
            return decision != null;
        }
    }

    private static final Comparator<Candidate> WEAKEST_FIRST = Comparator
            .comparingInt((Candidate candidate) -> rank(candidate.decision().verdict()))
            .thenComparingInt(Candidate::position);

    private PqcRuleOrder() {
    }

    /** @throws IllegalStateException when no rule matched, which the fallback rules make unreachable */
    static Candidate select(List<Candidate> candidates) {
        List<Candidate> matched = candidates.stream().filter(Candidate::matched).toList();
        for (Candidate candidate : matched) {
            boolean excluded = candidate.decision().verdict() == PqcVerdict.NOT_APPLICABLE;
            if (excluded != (candidate.entry().tier() == PqcRuleCatalog.Tier.EXCLUSION)) {
                throw new IllegalStateException(
                        "Rule " + candidate.entry().id() + " is catalogued in the wrong tier for its verdict");
            }
        }
        Optional<Candidate> exclusion = matched.stream().filter(PqcRuleOrder::isExclusion).findFirst();
        if (exclusion.isPresent()) {
            return exclusion.get();
        }
        Optional<Candidate> finding = matched
                .stream()
                .filter(candidate -> candidate.entry().tier() == PqcRuleCatalog.Tier.FINDING)
                .min(WEAKEST_FIRST);
        if (finding.isPresent()) {
            return finding.get();
        }
        return matched
                .stream()
                .filter(candidate -> candidate.entry().tier() == PqcRuleCatalog.Tier.FALLBACK)
                .findFirst()
                .orElseThrow(() -> new IllegalStateException("No rule matched the asset"));
    }

    private static boolean isExclusion(Candidate candidate) {
        return candidate.entry().tier() == PqcRuleCatalog.Tier.EXCLUSION;
    }

    /** Weakest first. {@code notApplicable} never reaches a comparison: an exclusion is selected before ranking. */
    static int rank(PqcVerdict verdict) {
        return switch (verdict) {
            case NOT_READY -> 0;
            case UNKNOWN, NOT_APPLICABLE -> 1;
            case READY -> 2;
        };
    }
}
