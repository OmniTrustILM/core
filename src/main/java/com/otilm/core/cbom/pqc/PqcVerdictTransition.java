package com.otilm.core.cbom.pqc;

import com.otilm.api.model.common.events.data.CryptoAssetPqcNotReadyEventData;
import com.otilm.api.model.core.cryptoasset.PqcVerdict;
import com.otilm.core.cbom.asset.ServedAssetType;
import com.otilm.core.model.cbom.PqcStaleVerdictRow;

/** Keeps the last decided verdict across inconclusive evaluations. */
public record PqcVerdictTransition(PqcVerdict previousVerdict, PqcVerdict lastDecidedVerdict, boolean shouldPublish) {

    public static PqcVerdictTransition decide(PqcVerdict current, PqcVerdict lastDecided, PqcVerdict next) {
        PqcVerdict previous = lastDecided;
        if (previous == null && decided(current)) {
            previous = current;
        }
        return new PqcVerdictTransition(previous, decided(next) ? next : previous,
                next == PqcVerdict.NOT_READY && previous != PqcVerdict.NOT_READY);
    }

    private static boolean decided(PqcVerdict verdict) {
        return verdict == PqcVerdict.READY || verdict == PqcVerdict.NOT_READY || verdict == PqcVerdict.NOT_APPLICABLE;
    }

    public CryptoAssetPqcNotReadyEventData eventData(PqcStaleVerdictRow row, String ruleId, String reason) {
        CryptoAssetPqcNotReadyEventData data = new CryptoAssetPqcNotReadyEventData();
        data.setCryptoAssetUuid(row.uuid());
        data.setAssetType(ServedAssetType.of(row.assetType()));
        data.setName(row.name());
        data.setAlgorithmFamily(row.algorithmFamily());
        data.setPqcRuleId(ruleId);
        data.setPqcReason(reason);
        data.setPreviousVerdict(previousVerdict);
        return data;
    }
}
