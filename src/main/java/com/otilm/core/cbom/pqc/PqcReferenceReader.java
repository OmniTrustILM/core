package com.otilm.core.cbom.pqc;

import com.fasterxml.jackson.databind.JsonNode;
import com.otilm.api.model.core.cryptoasset.CryptographicAssetType;
import com.otilm.api.model.core.cryptoasset.PqcVerdict;
import com.otilm.core.cbom.asset.identity.AssetReferences;
import com.otilm.core.dao.repository.cbom.CryptoAssetReferenceRepository;
import com.otilm.core.model.cbom.CryptoAssetReferenceKind;
import com.otilm.core.model.cbom.PqcStaleVerdictRow;
import jakarta.persistence.Tuple;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import org.springframework.stereotype.Component;

/**
 * Reads what the rows about to be evaluated reference, one statement per page of rows. Every evaluator caller -- the
 * sweep, the ingest and the explanation -- goes through here, so the three cannot read references differently.
 */
@Component
public class PqcReferenceReader {

    private final CryptoAssetReferenceRepository referenceRepository;

    public PqcReferenceReader(CryptoAssetReferenceRepository referenceRepository) {
        this.referenceRepository = referenceRepository;
    }

    /** @return the references of every certificate and protocol among the rows, by asset */
    public Map<UUID, List<PqcReferences.Reference>> load(List<PqcStaleVerdictRow> rows) {
        List<UUID> referrers = rows
                .stream()
                .filter(row -> PqcReferenceRules.decides(row.assetType()))
                .map(PqcStaleVerdictRow::uuid)
                .toList();
        Map<UUID, List<PqcReferences.Reference>> loaded = new HashMap<>();
        if (referrers.isEmpty()) {
            return loaded;
        }
        for (Tuple row : referenceRepository.findElectedReferences(referrers)) {
            loaded.computeIfAbsent(row.get("asset_uuid", UUID.class), uuid -> new ArrayList<>()).add(referenceOf(row));
        }
        return loaded;
    }

    /** One row's references, with the suites its own payload records. */
    public static PqcReferences forRow(PqcStaleVerdictRow row, JsonNode mergedCryptoProperties,
            Map<UUID, List<PqcReferences.Reference>> loaded) {
        if (!PqcReferenceRules.decides(row.assetType())) {
            return PqcReferences.NONE;
        }
        return PqcReferences.of(loaded.getOrDefault(row.uuid(), List.of()), cipherSuites(mergedCryptoProperties));
    }

    private static List<String> cipherSuites(JsonNode mergedCryptoProperties) {
        JsonNode protocol = mergedCryptoProperties == null ? null : mergedCryptoProperties.get("protocolProperties");
        JsonNode suites = protocol == null ? null : protocol.get("cipherSuites");
        if (suites == null || !suites.isArray()) {
            return List.of();
        }
        List<String> labels = new ArrayList<>(suites.size());
        for (int i = 0; i < suites.size(); i++) {
            if (suites.get(i).isObject()) {
                labels.add(AssetReferences.suiteLabel(suites.get(i), i));
            }
        }
        return labels;
    }

    private static PqcReferences.Reference referenceOf(Tuple row) {
        String targetType = row.get("target_type", String.class);
        String targetVerdict = row.get("target_verdict", String.class);
        return new PqcReferences.Reference(CryptoAssetReferenceKind.valueOf(row.get("kind", String.class)),
                row.get("ref", String.class), row.get("suite", String.class), row.get("target_asset_uuid", UUID.class),
                targetType == null ? null : CryptographicAssetType.valueOf(targetType),
                targetVerdict == null ? null : PqcVerdict.valueOf(targetVerdict),
                row.get("target_rule_id", String.class), row.get("target_primitive", String.class));
    }
}
