package com.otilm.core.cbom.pqc;

import com.fasterxml.jackson.databind.JsonNode;
import com.otilm.api.model.core.cryptoasset.CryptographicAssetType;
import com.otilm.api.model.core.cryptoasset.PqcVerdict;
import com.otilm.core.cbom.asset.CryptoAssetIdentityFields;
import com.otilm.core.cbom.asset.identity.AsciiText;
import com.otilm.core.cbom.asset.identity.AssetNormalizer;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.regex.Pattern;
import java.util.stream.Collectors;
import java.util.stream.Stream;
import org.springframework.context.annotation.Lazy;
import org.springframework.stereotype.Component;

/**
 * Decides one asset's post-quantum readiness. Pure: storing the result is the caller's separate call, which is what
 * lets the whole rule set be tested without Spring or a database.
 *
 * <p>
 * {@link #fromStoredRow} is the only way to build a {@link PqcRuleInput}: every caller, ingest included, evaluates the
 * row as the database holds it after the upsert and the merge, so two callers reading one row cannot disagree.
 */
@Component
@Lazy
public class PqcEvaluator {

    /** The {@code -768} a hybrid component may carry, which the family tables do not spell. */
    private static final Pattern FAMILY_SIZE_SUFFIX = Pattern.compile("-\\d+$");

    /**
     * {@code variant} is {@code residue|sizes+token,token}, so three separators -- and {@code +} is also the last
     * character of the {@code sphincs+} token, which is why a {@code +} splits only when a token follows it.
     */
    private static final Pattern VARIANT_SEPARATORS = Pattern.compile("[,|]|\\+(?=[^,|+])");

    /**
     * The one-time-signature discriminator the LMS grammar keeps in the residue; glued to its neighbours in
     * {@code otsnw}.
     */
    private static final String ONE_TIME_SIGNATURE = "ots";

    private static final Set<String> STATEFUL_HASH_SIGNATURES = Set.of("LMS", "XMSS");

    private static final PqcRule HYBRID_RULE = new PqcRule(PqcRules.HYBRID, PqcRuleInput::isHybrid, PqcVerdict.READY,
            "A hybrid construction; its readiness is that of its post-quantum component",
            List.of(PqcRules.ALGORITHM_FAMILY, PqcRules.HYBRID_COMPONENTS, PqcRules.NAME, PqcRules.VARIANT));

    private static final String RELATED_MATERIAL = "relatedCryptoMaterialProperties";
    private static final String ALGORITHM_PROPERTIES = "algorithmProperties";

    private static final String NIST_LEVEL = PqcRules.NIST_QUANTUM_SECURITY_LEVEL;

    /** The ratified "the producer said nothing" spelling for a material type, per core#2196's ruling C10. */
    private static final String MATERIAL_TYPE_UNKNOWN = "unknown";

    /** The ratified spellings, indexed by their separator-insensitive lookup key. */
    private static final Map<String, String> MATERIAL_TYPE_KEYS = Stream
            .of(PqcRules.SYMMETRIC_MATERIAL, PqcRules.NON_KEY_MATERIAL, Set.of("private-key", "public-key", "key-pair"))
            .flatMap(Set::stream)
            .collect(Collectors.toMap(AsciiText::lookupKey, spelling -> spelling));

    private final AssetNormalizer normalizer;
    private final List<PqcRule> rules;

    public PqcEvaluator(AssetNormalizer normalizer) {
        this.normalizer = normalizer;
        this.rules = PqcRules.rulesFor(normalizer);
    }

    /**
     * First match wins. @param nistQuantumSecurityLevel corroboration only; a parameter, so no predicate can reach it
     */
    public PqcDecision evaluate(PqcRuleInput input, Integer nistQuantumSecurityLevel) {
        for (PqcRule rule : rules) {
            if (rule.matches().test(input)) {
                return rule.id().equals(PqcRules.HYBRID)
                        ? hybridDecision(input, hybridComponentsOf(input), rule, nistQuantumSecurityLevel)
                        : decision(rule.verdict(), rule.id(), rule.reason(), rule.readsFields(), input,
                                nistQuantumSecurityLevel);
            }
        }
        // Past the table: an algorithm the grammar did not record as a hybrid, or key material the material rules did
        // not claim. A hybrid still decides before its family, because the family is whichever half the grammar
        // elected.
        List<String> hybrid = hybridComponentsOf(input);
        if (!hybrid.isEmpty()) {
            return hybridDecision(input, hybrid, HYBRID_RULE, nistQuantumSecurityLevel);
        }
        return componentOrFamilyDecision(input, nistQuantumSecurityLevel);
    }

    /**
     * The hybrid components the grammar recorded, widened by the secondary tokens.
     *
     * <p>
     * {@code AssetNormalizer.hybridComponents} tests membership against its own {@code PQC_FAMILIES}, which holds 25
     * tokens where the ratified tables name 33 pseudo-families -- the drift core#2196's ruling C12 exists to end. So
     * {@code X25519-HAWK-512} recorded no components, elected its classical half and read {@code notReady} on that half
     * alone, which is the one outcome ruling (b) forbids. The ratified tables answer for all 33.
     */
    private List<String> hybridComponentsOf(PqcRuleInput input) {
        if (!input.hybridComponents().isEmpty()) {
            return input.hybridComponents();
        }
        if (PqcFamilies.of(ratifiedFamily(input.algorithmFamily())) != FamilyClass.SHOR_BREAKABLE) {
            return List.of();
        }
        List<String> components = new ArrayList<>();
        for (String token : secondaryTokens(input)) {
            FamilyClass disposition = dispositionOfToken(token);
            if (disposition != null && disposition.isPostQuantum()) {
                // Folded like the normalizer's own components, so the two paths record one spelling.
                components.add(AsciiText.fold(input.algorithmFamily()));
                components.add(token);
            }
        }
        return List.copyOf(components);
    }

    /**
     * A broken component decides before the family does.
     *
     * <p>
     * {@code HMAC-MD5} elects family {@code HMAC} and stores {@code md5} in the variant slot; {@code 3DES-CMAC} elects
     * {@code CMAC} and stores {@code 3des,des}; {@code ECIES-X25519-XSalsa20-Poly1305} elects {@code Poly1305} and
     * stores its key agreement beside it. Reading the family alone answered {@code ready} for all three. The
     * specification made those tokens identity-bearing precisely because dropping them "silently erases a weak-crypto
     * finding -- the one outcome an inventory must never produce", and the verdict path was doing exactly that.
     *
     * <p>
     * A family with no grammar rule -- {@code CMEA}, {@code Yarrow} -- survives into the variant as the asset's own
     * name, and the component rule then blamed a component the asset does not have. When that is the only weak token,
     * the asset <em>is</em> the family and is served as one.
     */
    private PqcDecision componentOrFamilyDecision(PqcRuleInput input, Integer nistQuantumSecurityLevel) {
        Map<String, FamilyClass> weak = weakSecondaryTokens(input);
        if (weak.isEmpty()) {
            return familyDecision(input, nistQuantumSecurityLevel);
        }
        if (input.algorithmFamily() == null && weak.size() == 1 && weak.containsKey(input.name())) {
            return familyDecision(input.withAlgorithmFamily(ratifiedFamily(input.name())), nistQuantumSecurityLevel);
        }
        // Already broken today outranks broken by a future quantum computer, whatever order the tokens came in.
        FamilyClass weakest = weak.containsValue(FamilyClass.CLASSICAL_LEGACY)
                ? FamilyClass.CLASSICAL_LEGACY
                : FamilyClass.SHOR_BREAKABLE;
        return decision(weakest.verdict(), weakest.ruleId() + "-COMPONENT", componentReason(weakest),
                List.of(PqcRules.ALGORITHM_FAMILY, PqcRules.VARIANT, PqcRules.NAME), input, nistQuantumSecurityLevel);
    }

    private static String componentReason(FamilyClass weakest) {
        return weakest == FamilyClass.CLASSICAL_LEGACY
                ? "A component named by this asset is already broken classically, so the construction inherits it"
                : "A component named by this asset rests on factorisation or a discrete logarithm, so the construction "
                        + "inherits its quantum vulnerability";
    }

    /** The secondary tokens that are classically broken or Shor-breakable, with their dispositions, in token order. */
    private Map<String, FamilyClass> weakSecondaryTokens(PqcRuleInput input) {
        Map<String, FamilyClass> weak = new LinkedHashMap<>();
        for (String token : secondaryTokens(input)) {
            FamilyClass disposition = dispositionOfToken(token);
            if (disposition == FamilyClass.CLASSICAL_LEGACY || disposition == FamilyClass.SHOR_BREAKABLE) {
                weak.put(token, disposition);
            }
        }
        return weak;
    }

    private List<String> secondaryTokens(PqcRuleInput input) {
        if (input.variant() == null || input.variant().isEmpty()) {
            return List.of();
        }
        return VARIANT_SEPARATORS.splitAsStream(input.variant()).filter(token -> !token.isEmpty()).toList();
    }

    /**
     * A hybrid's readiness is its post-quantum component's, not the fact that it has one: {@code X25519-ML-KEM-768} is
     * ready, {@code X25519-Kyber768} is not, because bare Kyber is a superseded draft. What holds unconditionally is
     * that the classical half never decides. Among several post-quantum components
     * {@link FamilyClass#byHybridPrecedence()} decides, so the answer does not depend on the order the name spelt them.
     */
    private PqcDecision hybridDecision(PqcRuleInput input, List<String> components, PqcRule rule,
            Integer nistQuantumSecurityLevel) {
        if (components.stream().noneMatch(this::isShorBreakable)) {
            // Not a hybrid, whatever the grammar recorded. AssetNormalizer counts any non-PQC secondary token as the
            // classical half, and every FIPS 205 and RFC 8391 parameter-set name carries a hash token -- so
            // SLH-DSA-SHAKE-256f and XMSSMT-SHA2_20/2_256 arrived here as hybrids. The verdict was right by luck,
            // because the post-quantum half wins either way, but the rule id and reason on the wire were false and an
            // operator filtering on PQC-STANDARDIZED missed every standards-spelled row. The hash token may still be
            // a broken one, so ML-KEM-MD5 goes through the component check like any other name.
            return componentOrFamilyDecision(input, nistQuantumSecurityLevel);
        }
        PqcRuleInput hybrid = input.withHybridComponents(components);
        FamilyClass decisive = components
                .stream()
                .map(this::dispositionOfComponent)
                .filter(Objects::nonNull)
                .filter(FamilyClass::isPostQuantum)
                .min(FamilyClass.byHybridPrecedence())
                .orElse(null);
        if (decisive == null) {
            // Recorded as hybrid by the grammar, but no component resolves to a post-quantum family this table knows.
            // Not notReady: the classical half must not decide a hybrid, which is the one thing ruling (b) settles.
            return decision(PqcVerdict.UNKNOWN, "PQC-HYBRID-UNRESOLVED",
                    "A hybrid construction whose post-quantum component resolves to no ratified family",
                    rule.readsFields(), hybrid, nistQuantumSecurityLevel);
        }
        String reason = decisive.verdict() == PqcVerdict.READY
                ? rule.reason()
                : "A hybrid construction whose post-quantum component is not standardised: " + decisive.reason();
        return decision(decisive.verdict(), rule.id() + "-" + decisive.ruleId(), reason, rule.readsFields(), hybrid,
                nistQuantumSecurityLevel);
    }

    private boolean isShorBreakable(String component) {
        return dispositionOfComponent(component) == FamilyClass.SHOR_BREAKABLE;
    }

    private FamilyClass dispositionOfComponent(String component) {
        return PqcFamilies.of(ratifiedFamily(FAMILY_SIZE_SUFFIX.matcher(component).replaceFirst("")));
    }

    private PqcDecision familyDecision(PqcRuleInput input, Integer nistQuantumSecurityLevel) {
        FamilyClass disposition = PqcFamilies.of(ratifiedFamily(input.algorithmFamily()));
        if (disposition == null) {
            return decision(PqcVerdict.UNKNOWN, PqcRules.FAMILY_UNRESOLVED,
                    "The recorded properties resolve to no ratified algorithm family, so no rule can classify it",
                    List
                            .of(PqcRules.ASSET_TYPE, PqcRules.MATERIAL_TYPE, PqcRules.ALGORITHM_FAMILY, PqcRules.NAME,
                                    PqcRules.VARIANT),
                    input, nistQuantumSecurityLevel);
        }
        if (disposition == FamilyClass.FAMILY_AMBIGUOUS && input.curve() != null) {
            // Every curve the tables ratify under GOST is a GOST R 34.10 curve, so a curve on an ambiguous family names
            // the EC signature scheme; the hash and the block ciphers carry none. Exact, not a heuristic: the curve
            // column is populated only from the ratified curve tables.
            FamilyClass signature = FamilyClass.SHOR_BREAKABLE;
            return decision(signature.verdict(), signature.ruleId(), signature.reason(),
                    List.of(PqcRules.ALGORITHM_FAMILY, PqcRules.CURVE, PqcRules.VARIANT), input,
                    nistQuantumSecurityLevel);
        }
        if (disposition == FamilyClass.PQC_STANDARDIZED && isOneTimeSignature(input)) {
            return decision(PqcVerdict.UNKNOWN, "PQC-ONE-TIME-SIGNATURE",
                    "A one-time signature scheme, which SP 800-208 approves only as a component within LMS or XMSS and "
                            + "not on its own, so the family alone cannot affirm it",
                    List.of(PqcRules.ALGORITHM_FAMILY, PqcRules.VARIANT), input, nistQuantumSecurityLevel);
        }
        return decision(disposition.verdict(), disposition.ruleId(), disposition.reason(),
                List.of(PqcRules.ALGORITHM_FAMILY, PqcRules.VARIANT), input, nistQuantumSecurityLevel);
    }

    /**
     * The LMS grammar keys LM-OTS, LMS and HSS-LMS alike and keeps the {@code ots} and {@code hss} discriminators in
     * the residue on purpose: key reuse is what tells a one-time signature from the many-time scheme built over it.
     */
    private boolean isOneTimeSignature(PqcRuleInput input) {
        return STATEFUL_HASH_SIGNATURES.contains(input.algorithmFamily())
                && secondaryTokens(input).stream().anyMatch(token -> token.contains(ONE_TIME_SIGNATURE));
    }

    /**
     * Any spelling onto the ratified one, and not optional: the column is case-folded while {@code AssetNormalizer}
     * compares family tokens case-sensitively, so passing a folded {@code x-wing} straight back took the non-hybrid
     * path and re-derived different components.
     */
    private String ratifiedFamily(String anySpelling) {
        return normalizer.tables().familyToken(anySpelling);
    }

    /**
     * A component token onto its ratified family, whole spelling first.
     *
     * <p>
     * The size suffix is stripped only as a fallback, because several families carry a digit that is part of the name:
     * stripping first turns {@code sha-1} into {@code sha} and {@code sha-2} into {@code sha}, which resolve to nothing
     * -- so {@code HMAC-SHA1} read {@code ready}. The normalizer documents the same trap on its own token folding.
     */
    private FamilyClass dispositionOfToken(String token) {
        FamilyClass whole = PqcFamilies.of(ratifiedFamily(token));
        if (whole != null) {
            return whole;
        }
        return dispositionOfComponent(token);
    }

    // ---- The input shape ------------------------------------------------------------------------------------------

    /**
     * {@code hybridComponents} is re-derived, not read: it is out-of-key by construction and has no column.
     *
     * <p>
     * The material tier derives no family -- {@code AssetNormalizer} leaves it null for every
     * {@code related-crypto-material} component, with or without an {@code algorithmRef} -- so a private key whose own
     * name says {@code RSA-2048} reached the rules with nothing to classify. The name is a column, so reading the
     * family out of it is available to every caller. Confined to material: on an algorithm row a null family is the
     * normalizer's decision, a cipher suite above all, and stands.
     */
    public PqcRuleInput fromStoredRow(CryptoAssetIdentityFields fields, JsonNode mergedCryptoProperties) {
        String family = ratifiedFamily(fields.algorithmFamily());
        if (family == null && fields.assetType() == CryptographicAssetType.RELATED_CRYPTO_MATERIAL) {
            family = ratifiedFamily(normalizer.familyFromName(fields.name()));
        }
        List<String> hybrid = normalizer.hybridComponents(family, normalizer.secondaryTokens(fields.name(), family));
        return new PqcRuleInput(fields.assetType(), family, parameterSet(fields.parameterSet()), fields.curve(),
                fields.mode(), fields.padding(), fields.variant(), fields.name(), hybrid,
                materialType(mergedCryptoProperties), materialSize(mergedCryptoProperties));
    }

    /** The normalizer's routing vocabulary onto the column's enum; the unroutable tier has no producer spelling. */
    public static CryptographicAssetType assetTypeOf(String routed) {
        if (routed == null) {
            return CryptographicAssetType.UNROUTABLE;
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
     * The ratified {@code unknown} spelling reads as absent, and lookup is separator-insensitive because producers
     * camelCase these vocabularies. core#2196's ruling C10 keeps {@code unknown} as a value; this is its second reader,
     * and takes it as "the producer said nothing" rather than a fourth arm of the material partition.
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
        // lookupKey, not toLowerCase: producers camelCase these vocabularies, and MaterialRedaction already matches
        // them separator-insensitively. `secretKey` and `SECRET_KEY` must reach the same arm as `secret-key`.
        String folded = AsciiText.lookupKey(type.textValue());
        if (folded.isEmpty() || AsciiText.lookupKey(MATERIAL_TYPE_UNKNOWN).equals(folded)) {
            return null;
        }
        return MATERIAL_TYPE_KEYS.getOrDefault(folded, folded);
    }

    /**
     * Held to the ratified size band the normalizer applies to name-derived sizes, so {@code -1}, {@code 0} and a byte
     * count are absent rather than republished as a strength. Below the floor bits and bytes cannot be told apart:
     * {@code 32} is AES-256 in bytes and a broken key in bits, and the rules must not guess.
     */
    Integer materialSize(JsonNode cryptoProperties) {
        JsonNode material = cryptoProperties == null ? null : cryptoProperties.get(RELATED_MATERIAL);
        if (material == null || !material.isObject()) {
            return null;
        }
        JsonNode size = material.get("size");
        // canConvertToInt, not intValue: a size of 4294967424 truncates to 128 and reads as an adequate key.
        if (size == null || !size.isIntegralNumber() || !size.canConvertToInt()) {
            return null;
        }
        int bits = size.intValue();
        return bits >= normalizer.tables().sizeMin() && bits <= normalizer.tables().sizeMax() ? bits : null;
    }

    /** Non-integral reads as absent: one producer wrote a string there, and the wire field promises a level. */
    public static Integer nistQuantumSecurityLevel(JsonNode cryptoProperties) {
        JsonNode algorithm = cryptoProperties == null ? null : cryptoProperties.get(ALGORITHM_PROPERTIES);
        if (algorithm == null || !algorithm.isObject()) {
            return null;
        }
        JsonNode level = algorithm.get(NIST_LEVEL);
        return level != null && level.isIntegralNumber() && level.canConvertToInt() ? level.intValue() : null;
    }

    // ---- Evidence -------------------------------------------------------------------------------------------------

    /** Projected from a closed switch, never collected by watching what the predicate read. */
    private static PqcDecision decision(PqcVerdict verdict, String ruleId, String reason, List<String> readsFields,
            PqcRuleInput input, Integer nistQuantumSecurityLevel) {
        return new PqcDecision(verdict, ruleId, reason,
                projectEvidence(readsFields, input, nistQuantumSecurityLevel, ruleId));
    }

    static Map<String, Object> projectEvidence(List<String> readsFields, PqcRuleInput input,
            Integer nistQuantumSecurityLevel, String ruleId) {
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
            evidence.put(PqcRules.NIST_QUANTUM_SECURITY_LEVEL, nistQuantumSecurityLevel);
        }
        return evidence;
    }

    private static Object valueOf(String field, PqcRuleInput input, Integer nistQuantumSecurityLevel) {
        return switch (field) {
            case PqcRules.ASSET_TYPE -> input.assetType() == null ? null : input.assetType().getCode();
            case PqcRules.ALGORITHM_FAMILY -> input.algorithmFamily();
            case PqcRules.PARAMETER_SET -> input.parameterSet();
            case PqcRules.CURVE -> input.curve();
            case "mode" -> input.mode();
            case "padding" -> input.padding();
            case PqcRules.VARIANT -> input.variant();
            case PqcRules.NAME -> input.name();
            case PqcRules.HYBRID_COMPONENTS -> input.hybridComponents().isEmpty() ? null : input.hybridComponents();
            case PqcRules.MATERIAL_TYPE -> input.materialType();
            case PqcRules.MATERIAL_SIZE -> input.materialSize();
            case PqcRules.NIST_QUANTUM_SECURITY_LEVEL -> nistQuantumSecurityLevel;
            default -> throw new IllegalStateException("Unhandled evaluated field: " + field);
        };
    }
}
