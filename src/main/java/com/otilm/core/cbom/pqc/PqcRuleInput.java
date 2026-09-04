package com.otilm.core.cbom.pqc;

import com.otilm.api.model.core.cryptoasset.CryptographicAssetType;
import java.util.List;

/**
 * Everything a readiness rule may read, and nothing else.
 *
 * <p>
 * <b>This record is the security boundary, not a convenience.</b> {@code crypto_asset.pqc_evaluated_fields} is served
 * verbatim to clients as {@code CryptographicAssetVerdictDto.evaluatedFields}, and {@code IdentityKeyExposureFence} is
 * lexical over source text: both ends of that channel are innocuously named ({@code pqcEvaluatedFields},
 * {@code evaluatedFields}, typed {@code Map<String, Object>}) and the map's keys are runtime data, so a green build
 * proves nothing about what travels in it. What keeps the identity key out is that it never enters here -- the
 * evaluator cannot record a field it was never given. The identity key, an alias canonical key and an absorbed key are
 * therefore absent by construction rather than filtered on the way out.
 *
 * <p>
 * <b>{@code nistQuantumSecurityLevel} is deliberately not a member.</b> It is producer-supplied and observed to
 * disagree across producers for one asset -- SHA-384 carries 0, 2 and 3 in the corpus, SHA-256 adds 5, and one producer
 * wrote a non-numeric string. It may corroborate a verdict and it may never decide one, so it is kept out of the type a
 * rule predicate can see. A rule cannot read what it cannot reach; the evaluator records the level beside the decision
 * instead.
 *
 * @param hybridComponents the constructions a hybrid name names, folded and possibly carrying a parameter-set size
 * ({@code ml-kem-768}), never a bare family spelling to compare against the tables directly
 * @param materialSize the key size a related-crypto-material component declared, or {@code null} when it declared none
 * -- which is the common case, and the reason a symmetric key without one cannot be called ready
 */
public record PqcRuleInput(CryptographicAssetType assetType, String algorithmFamily, Integer parameterSet, String curve,
        String mode, String padding, String variant, String name, List<String> hybridComponents, String materialType,
        Integer materialSize) {

    public PqcRuleInput {
        hybridComponents = hybridComponents == null ? List.of() : List.copyOf(hybridComponents);
    }

    public boolean isHybrid() {
        return !hybridComponents.isEmpty();
    }
}
