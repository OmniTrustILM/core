package com.otilm.core.cbom.pqc;

import com.fasterxml.jackson.databind.JsonNode;
import com.otilm.api.model.core.cryptoasset.CryptographicAssetType;
import com.otilm.api.model.core.cryptoasset.PqcVerdict;
import com.otilm.core.cbom.asset.CryptoAssetIdentityFields;
import com.otilm.core.cbom.asset.identity.AssetNormalizer;
import com.otilm.core.cbom.asset.identity.IdentityTables;
import com.otilm.core.cbom.asset.identity.NormalizedAsset;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.regex.Pattern;
import org.springframework.stereotype.Component;

/**
 * Decides one asset's post-quantum readiness, and does nothing else.
 *
 * <p>
 * <b>Pure, and deliberately not a persistence path.</b> {@link #evaluate} takes values and returns a
 * {@link PqcDecision}; storing it is the caller's separate call to {@code CryptoAssetPqcVerdictWriter}. That split is
 * what lets the whole rule set be unit-tested without a Spring context or a database, which matters because the rules
 * are where the cryptographic judgement lives and the persistence is a single {@code UPDATE} already pinned by
 * {@code CryptoAssetInventoryITest}.
 *
 * <p>
 * <b>Two callers, two input shapes, one answer.</b> Ingest (core#2073) holds a {@link NormalizedAsset} in memory. The
 * re-evaluation sweep holds only a stored row: the ten identity columns plus one elected source's
 * {@code cryptoProperties}. {@link #fromNormalized} and {@link #fromStoredRow} exist to make those two produce the same
 * {@link PqcRuleInput}, and they are the part of this class most able to go quietly wrong -- see
 * {@link #ratifiedFamily} for the casing trap that made the two disagree about exactly the hybrids the rules exist to
 * catch.
 */
@Component
public class PqcEvaluator {

    /** The {@code -768} a hybrid component may carry, which the family tables do not spell. */
    private static final Pattern FAMILY_SIZE_SUFFIX = Pattern.compile("-\\d+$");

    private static final String RELATED_MATERIAL = "relatedCryptoMaterialProperties";
    private static final String ALGORITHM_PROPERTIES = "algorithmProperties";

    /** The ratified "the producer said nothing" spelling for a material type, per core#2196's ruling C10. */
    private static final String MATERIAL_TYPE_UNKNOWN = "unknown";

    private final AssetNormalizer normalizer;

    public PqcEvaluator(AssetNormalizer normalizer) {
        this.normalizer = normalizer;
    }

    public PqcEvaluator() {
        this(new AssetNormalizer(IdentityTables.load()));
    }

    /**
     * Runs the rule set, first match wins.
     *
     * @param nistQuantumSecurityLevel the producer's claim, which may corroborate a verdict and may never decide one.
     * It is a parameter rather than a field of {@link PqcRuleInput} precisely so that no predicate can reach it: it is
     * observed to disagree across producers for one asset, so a rule reading it would make the verdict a function of
     * which producer synced last.
     */
    public PqcDecision evaluate(PqcRuleInput input, Integer nistQuantumSecurityLevel) {
        for (PqcRule rule : PqcRules.preFamilyRules()) {
            if (rule.matches().test(input)) {
                return rule.id().equals("PQC-HYBRID")
                        ? hybridDecision(input, rule, nistQuantumSecurityLevel)
                        : decision(rule.verdict(), rule.id(), rule.reason(), rule.readsFields(), input,
                                nistQuantumSecurityLevel);
            }
        }
        return familyDecision(input, nistQuantumSecurityLevel);
    }

    /**
     * A hybrid's readiness is its post-quantum component's, not merely the fact that it has one.
     *
     * <p>
     * The distinction is the whole point: {@code X25519-ML-KEM-768} is ready because ML-KEM is standardised, while
     * {@code X25519-Kyber768} is not, because Kyber is a superseded draft that is not wire-compatible with the scheme
     * that replaced it. A rule testing only for the presence of a post-quantum component would report the second as
     * migrated, which is the "silently erasing a weak-crypto finding" outcome an inventory must never produce. What the
     * hybrid rule does buy unconditionally is that the classical half never decides: a hybrid is never {@code notReady}
     * because it contains X25519.
     */
    private PqcDecision hybridDecision(PqcRuleInput input, PqcRule rule, Integer nistQuantumSecurityLevel) {
        FamilyClass strongest = null;
        for (String component : input.hybridComponents()) {
            FamilyClass disposition = PqcFamilies
                    .of(ratifiedFamily(FAMILY_SIZE_SUFFIX.matcher(component).replaceFirst("")));
            if (disposition == FamilyClass.PQC_STANDARDIZED) {
                strongest = disposition;
                break;
            }
            if (isPostQuantum(disposition) && strongest == null) {
                strongest = disposition;
            }
        }
        if (strongest == null) {
            // Recorded as hybrid by the grammar, but no component resolves to a post-quantum family this table knows.
            // Not notReady: the classical half must not decide a hybrid, which is the one thing ruling (b) settles.
            return decision(PqcVerdict.UNKNOWN, "PQC-HYBRID-UNRESOLVED",
                    "A hybrid construction whose post-quantum component resolves to no ratified family",
                    rule.readsFields(), input, nistQuantumSecurityLevel);
        }
        String reason = strongest == FamilyClass.PQC_STANDARDIZED
                ? rule.reason()
                : "A hybrid construction whose post-quantum component is not standardised: " + strongest.reason();
        return decision(strongest.verdict(), rule.id() + "-" + strongest.ruleId(), reason, rule.readsFields(), input,
                nistQuantumSecurityLevel);
    }

    private static boolean isPostQuantum(FamilyClass disposition) {
        return disposition == FamilyClass.PQC_STANDARDIZED || disposition == FamilyClass.PQC_PRESTANDARD
                || disposition == FamilyClass.PQC_BROKEN || disposition == FamilyClass.PQC_HYBRID;
    }

    private PqcDecision familyDecision(PqcRuleInput input, Integer nistQuantumSecurityLevel) {
        FamilyClass disposition = PqcFamilies.of(ratifiedFamily(input.algorithmFamily()));
        if (disposition == null) {
            return decision(PqcVerdict.UNKNOWN, PqcRules.FAMILY_UNRESOLVED,
                    "The recorded properties resolve to no ratified algorithm family, so no rule can classify it",
                    List.of("algorithmFamily", "name"), input, nistQuantumSecurityLevel);
        }
        return decision(disposition.verdict(), disposition.ruleId(), disposition.reason(),
                List.of("algorithmFamily", "parameterSet"), input, nistQuantumSecurityLevel);
    }

    /**
     * Resolves any spelling of a family onto the ratified one, and it is not optional.
     *
     * <p>
     * The stored column holds {@link CryptoAssetIdentityFields#normalized()}'s output, which is case-folded, while
     * {@code AssetNormalizer} compares family tokens case-sensitively -- {@code HYBRID_FAMILIES.contains(winner)}
     * against {@code Set.of("X-Wing")}, and {@code rule.family().equals(winner)}. Passing the folded {@code x-wing}
     * straight back in therefore took the non-hybrid scan path and re-derived different components, so the sweep and
     * ingest disagreed about exactly the hybrid the acceptance criteria name. {@code IdentityTables.familyToken} is
     * fold-insensitive and its map includes the pseudo-families, so it is the one lookup that answers for both shapes.
     */
    private String ratifiedFamily(String anySpelling) {
        return normalizer.tables().familyToken(anySpelling);
    }

    // ---- The two input shapes -------------------------------------------------------------------------------------

    /**
     * The ingest shape: everything already derived, hybrids included.
     *
     * <p>
     * <b>It evaluates the row that is about to be stored, not the derivation in hand.</b> The identity columns are
     * built and folded through {@link CryptoAssetIdentityFields#normalized()} first, which is the same value the sweep
     * will later read back. Skipping that step made ingest record the producer's raw spelling in
     * {@code pqc_evaluated_fields} while the sweep recorded the folded one, so a rule-set bump rewrote the evidence of
     * every asset whose name was not already lower-case -- the verdict and the rule id agreed, and the evidence quietly
     * did not. Sharing one mapping makes the two agree by construction rather than by a test noticing.
     *
     * <p>
     * What is <em>not</em> shared is {@code hybridComponents}: they are taken from the derivation here and re-derived
     * from the stored columns in {@link #fromStoredRow}, because they have no column to be read from. That is the one
     * genuine divergence risk between the shapes, and it is what {@code PqcParityTest} exists to hold.
     */
    public PqcRuleInput fromNormalized(NormalizedAsset asset, JsonNode cryptoProperties) {
        CryptoAssetIdentityFields stored = CryptoAssetIdentityFields
                .of(assetTypeOf(asset.assetType()), asset)
                .normalized();
        return new PqcRuleInput(stored.assetType(), ratifiedFamily(stored.algorithmFamily()),
                parameterSet(stored.parameterSet()), stored.curve(), stored.mode(), stored.padding(), stored.variant(),
                stored.name(), asset.hybridComponents(), materialType(cryptoProperties),
                materialSize(cryptoProperties));
    }

    /**
     * The sweep shape: ten typed columns and one elected source's payload.
     *
     * <p>
     * {@code hybridComponents} is re-derived rather than read, because it is out-of-key by construction and therefore
     * has no column. Adding one would be a schema change this story does not have, and both the identity fence and the
     * merge election assume the shipped column set -- so the sweep pays a re-derivation instead, through the same
     * public entry points the normalizer offers ingest.
     */
    public PqcRuleInput fromStoredRow(CryptoAssetIdentityFields fields, JsonNode mergedCryptoProperties) {
        String family = ratifiedFamily(fields.algorithmFamily());
        List<String> hybrid = normalizer.hybridComponents(family, normalizer.secondaryTokens(fields.name(), family));
        return new PqcRuleInput(fields.assetType(), family, parameterSet(fields.parameterSet()), fields.curve(),
                fields.mode(), fields.padding(), fields.variant(), fields.name(), hybrid,
                materialType(mergedCryptoProperties), materialSize(mergedCryptoProperties));
    }

    /**
     * The routed asset-type spelling as the column's enum. Public because the ingest path needs the same mapping to
     * build the row this evaluator later reads back, and two copies of it would be a way for the two shapes to disagree
     * about a certificate.
     */
    public static CryptographicAssetType assetTypeOf(String routed) {
        if (routed == null) {
            return null;
        }
        return switch (routed) {
            case "algorithm" -> CryptographicAssetType.ALGORITHM;
            case "certificate" -> CryptographicAssetType.CERTIFICATE;
            case "protocol" -> CryptographicAssetType.PROTOCOL;
            case "related-crypto-material" -> CryptographicAssetType.RELATED_CRYPTO_MATERIAL;
            default -> CryptographicAssetType.UNROUTABLE;
        };
    }

    private static Integer parameterSet(String stored) {
        if (stored == null) {
            return null;
        }
        try {
            return Integer.valueOf(stored.trim());
        } catch (NumberFormatException e) {
            // The column is text and a producer can put anything in it. A parameter set that is not a number cannot
            // participate in a size comparison, and reading it as absent is what the ingest shape already does.
            return null;
        }
    }

    /**
     * The material type, with the ratified {@code unknown} spelling read as absent.
     *
     * <p>
     * core#2196's ruling C10 keeps {@code unknown} as a value of the material-type vocabulary, deliberately
     * inconsistent with the mode slot which reads it as absent. This rule set is that vocabulary's second reader, and
     * it takes the mode slot's reading: "the producer told us nothing" must not become a fourth arm of the material
     * partition, or a row with no stated type would be classified as though it had one.
     */
    static String materialType(JsonNode cryptoProperties) {
        JsonNode material = cryptoProperties == null ? null : cryptoProperties.get(RELATED_MATERIAL);
        if (material == null || !material.isObject()) {
            return null;
        }
        JsonNode type = material.get("type");
        if (type == null || !type.isTextual() || type.textValue().isBlank()) {
            return null;
        }
        String folded = type.textValue().trim().toLowerCase(Locale.ROOT);
        return MATERIAL_TYPE_UNKNOWN.equals(folded) ? null : folded;
    }

    static Integer materialSize(JsonNode cryptoProperties) {
        JsonNode material = cryptoProperties == null ? null : cryptoProperties.get(RELATED_MATERIAL);
        if (material == null || !material.isObject()) {
            return null;
        }
        JsonNode size = material.get("size");
        return size != null && size.isIntegralNumber() ? size.intValue() : null;
    }

    /**
     * The producer's quantum-security-level claim, or {@code null}.
     *
     * <p>
     * A non-integral value reads as absent rather than as a string: one corpus producer wrote a non-numeric string
     * there, and carrying it into the evidence map would put producer text on the wire under a field name that promises
     * a level.
     */
    public static Integer nistQuantumSecurityLevel(JsonNode cryptoProperties) {
        JsonNode algorithm = cryptoProperties == null ? null : cryptoProperties.get(ALGORITHM_PROPERTIES);
        if (algorithm == null || !algorithm.isObject()) {
            return null;
        }
        JsonNode level = algorithm.get("nistQuantumSecurityLevel");
        return level != null && level.isIntegralNumber() ? level.intValue() : null;
    }

    // ---- Evidence -------------------------------------------------------------------------------------------------

    /**
     * Projects the deciding rule's declared inputs, and refuses anything else.
     *
     * <p>
     * Projected from a closed switch rather than collected by watching what the predicate read: what reaches a client
     * is then a decision recorded in the rule, not a by-product of how a lambda happened to be written. The honest
     * limit is that a predicate <em>can</em> read a field it did not declare -- the evidence would then be incomplete,
     * though never wrong, and never carrying anything {@link PqcRuleInput} does not hold.
     */
    private static PqcDecision decision(PqcVerdict verdict, String ruleId, String reason, List<String> readsFields,
            PqcRuleInput input, Integer nistQuantumSecurityLevel) {
        Map<String, Object> evidence = new LinkedHashMap<>();
        for (String field : readsFields) {
            if (!PqcRules.EVIDENCE_FIELDS.contains(field)) {
                throw new IllegalStateException(
                        "Rule " + ruleId + " declares an evaluated field outside the allowlist: " + field);
            }
            Object value = valueOf(field, input, nistQuantumSecurityLevel);
            if (value != null) {
                evidence.put(field, value);
            }
        }
        if (nistQuantumSecurityLevel != null) {
            // Recorded on every decision, never read by one: it is the corroboration an operator can check the verdict
            // against, and keeping it out of the rules is what stops a producer's disagreement from moving a verdict.
            evidence.put("nistQuantumSecurityLevel", nistQuantumSecurityLevel);
        }
        return new PqcDecision(verdict, ruleId, reason, evidence);
    }

    private static Object valueOf(String field, PqcRuleInput input, Integer nistQuantumSecurityLevel) {
        return switch (field) {
            case "assetType" -> input.assetType() == null ? null : input.assetType().getCode();
            case "algorithmFamily" -> input.algorithmFamily();
            case "parameterSet" -> input.parameterSet();
            case "curve" -> input.curve();
            case "mode" -> input.mode();
            case "padding" -> input.padding();
            case "variant" -> input.variant();
            case "name" -> input.name();
            case "hybridComponents" -> input.hybridComponents().isEmpty() ? null : input.hybridComponents();
            case "materialType" -> input.materialType();
            case "materialSize" -> input.materialSize();
            case "nistQuantumSecurityLevel" -> nistQuantumSecurityLevel;
            default -> throw new IllegalStateException("Unhandled evaluated field: " + field);
        };
    }
}
