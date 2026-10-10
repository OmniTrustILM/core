package com.otilm.core.cbom.pqc;

import com.fasterxml.jackson.databind.JsonNode;
import com.otilm.api.model.core.cryptoasset.CryptographicAssetType;
import com.otilm.api.model.core.cryptoasset.PqcExplanationStepOutcome;
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
import java.util.TreeSet;
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
 * Every catalogue rule that applies to the asset's type is evaluated and {@link PqcRuleOrder} selects the deciding one,
 * so {@link #evaluate} and {@link #explain} are one computation: the explanation lays out the same candidates the
 * verdict was selected from.
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

    private static final List<String> FAMILY_FIELDS = List.of(PqcRules.ALGORITHM_FAMILY, PqcRules.VARIANT);

    private static final List<String> HYBRID_FIELDS = List
            .of(PqcRules.ALGORITHM_FAMILY, PqcRules.HYBRID_COMPONENTS, PqcRules.NAME, PqcRules.VARIANT);

    private static final List<String> COMPONENT_FIELDS = List
            .of(PqcRules.ALGORITHM_FAMILY, PqcRules.HYBRID_COMPONENTS, PqcRules.VARIANT, PqcRules.NAME);

    private static final String RELATED_MATERIAL = "relatedCryptoMaterialProperties";
    private static final String ALGORITHM_PROPERTIES = "algorithmProperties";

    private static final String NIST_LEVEL = PqcRules.NIST_QUANTUM_SECURITY_LEVEL;

    private static final String NOT_MATCHED = "The rule's condition did not hold for this asset";

    /** The leading {@link PqcRules#INPUT_FIELDS} the asset's own row answers; the rest are its references. */
    private static final int OWN_INPUT_FIELDS = PqcRules.INPUT_FIELDS.indexOf(PqcRules.SUBJECT_PUBLIC_KEY_REF);

    /** The ratified "the producer said nothing" spelling for a material type. */
    private static final String MATERIAL_TYPE_UNKNOWN = "unknown";

    /** The ratified spellings, indexed by their separator-insensitive lookup key. */
    private static final Map<String, String> MATERIAL_TYPE_KEYS = Stream
            .of(PqcRules.SYMMETRIC_MATERIAL, PqcRules.NON_KEY_MATERIAL, Set.of("private-key", "public-key", "key-pair"))
            .flatMap(Set::stream)
            .collect(Collectors.toMap(AsciiText::lookupKey, spelling -> spelling));

    /** A rule whose id and reason are computed from what it reads, unlike a table rule's. */
    @FunctionalInterface
    private interface CodedRule {

        /** @return the decision, or {@code null} when the rule's condition does not hold */
        PqcDecision apply(Reading reading, Integer nistQuantumSecurityLevel);
    }

    private final AssetNormalizer normalizer;
    private final Map<String, PqcRule> tableRules;
    private final Map<String, CodedRule> codedRules;

    public PqcEvaluator(AssetNormalizer normalizer) {
        this.normalizer = normalizer;
        Map<String, PqcRule> table = new LinkedHashMap<>();
        PqcRules
                .rulesFor(normalizer, this::nameCarriesNoFinding, this::nameLeavesStrengthToSize)
                .forEach(rule -> table.put(rule.id(), rule));
        this.tableRules = Map.copyOf(table);
        this.codedRules = codedRules();
    }

    private Map<String, CodedRule> codedRules() {
        Map<String, CodedRule> rules = new LinkedHashMap<>();
        rules.put(PqcRules.CLASSICAL_LEGACY_COMPONENT, this::classicalLegacyComponent);
        rules.put(PqcRules.HYBRID, this::hybrid);
        rules.put(PqcRules.HYBRID_UNRESOLVED, this::hybridUnresolved);
        rules.put(PqcRules.CLASSICAL_SHOR_COMPONENT, this::classicalShorComponent);
        rules.put(PqcRules.FAMILY_UNRESOLVED, this::familyUnresolved);
        rules.put(FamilyClass.SHOR_BREAKABLE.ruleId(), this::classicalShor);
        rules.put(PqcRules.FAMILY_AMBIGUOUS_COMPONENT, this::ambiguousPrimitive);
        rules.put(PqcRules.CONSTRUCTION_UNINSTANTIATED, this::constructionUninstantiated);
        rules.put(PqcRules.PARAMETER_SET_UNREGISTERED, this::parameterSetUnregistered);
        rules.put(PqcRules.SYMMETRIC_UNDERSIZED, this::symmetricUndersized);
        rules.put(FamilyClass.QUANTUM_RESISTANT_SYMMETRIC.ruleId(), this::symmetricReady);
        rules.put(PqcRules.ONE_TIME_SIGNATURE, this::oneTimeSignature);
        for (FamilyClass disposition : List
                .of(FamilyClass.PQC_STANDARDIZED, FamilyClass.PQC_PRESTANDARD, FamilyClass.PQC_BROKEN,
                        FamilyClass.PQC_HYBRID, FamilyClass.CLASSICAL_LEGACY)) {
            rules.put(disposition.ruleId(), (reading, level) -> familyDisposition(reading, disposition, level));
        }
        rules.put(FamilyClass.FAMILY_AMBIGUOUS.ruleId(), this::familyAmbiguous);
        return Map.copyOf(rules);
    }

    /** {@link #evaluate(PqcRuleInput, Integer, PqcReferences)} for an asset that references nothing. */
    public PqcDecision evaluate(PqcRuleInput input, Integer nistQuantumSecurityLevel) {
        return evaluate(input, nistQuantumSecurityLevel, PqcReferences.NONE);
    }

    /**
     * @param nistQuantumSecurityLevel corroboration only; a parameter, so no predicate can reach it
     * @throws IllegalStateException when no catalogue rule applies to the asset's type
     */
    public PqcDecision evaluate(PqcRuleInput input, Integer nistQuantumSecurityLevel, PqcReferences references) {
        return PqcRuleOrder.select(candidates(input, nistQuantumSecurityLevel, references)).decision();
    }

    public PqcExplanation explain(PqcRuleInput input, Integer nistQuantumSecurityLevel) {
        return explain(input, nistQuantumSecurityLevel, PqcReferences.NONE);
    }

    /**
     * {@link #evaluate}, with every catalogue rule the asset's type is tested against: matched or not, and which one
     * the order selected.
     */
    public PqcExplanation explain(PqcRuleInput input, Integer nistQuantumSecurityLevel, PqcReferences references) {
        List<PqcRuleOrder.Candidate> candidates = candidates(input, nistQuantumSecurityLevel, references);
        PqcRuleOrder.Candidate decided = PqcRuleOrder.select(candidates);
        List<PqcExplanation.Step> steps = new ArrayList<>(candidates.size());
        for (PqcRuleOrder.Candidate candidate : candidates) {
            steps.add(step(candidate, candidate == decided));
        }
        return new PqcExplanation(decided.decision(), steps);
    }

    private static PqcExplanation.Step step(PqcRuleOrder.Candidate candidate, boolean decided) {
        PqcRuleCatalog.Entry entry = candidate.entry();
        if (!candidate.matched()) {
            return new PqcExplanation.Step(entry.id(), entry.title(), PqcExplanationStepOutcome.NOT_MATCHED, null,
                    candidate.notMatched(), candidate.evidence(), null);
        }
        PqcDecision decision = candidate.decision();
        PqcExplanationStepOutcome outcome;
        if (!decided) {
            outcome = PqcExplanationStepOutcome.MATCHED;
        } else {
            outcome = decision.referencedAssetUuid() == null
                    ? PqcExplanationStepOutcome.DECIDED
                    : PqcExplanationStepOutcome.RESOLVED;
        }
        return new PqcExplanation.Step(decision.ruleId(), entry.title(), outcome, decision.verdict(), decision.reason(),
                decision.evaluatedFields(), decision.referencedAssetUuid());
    }

    /** Every catalogue rule for the asset's type, evaluated, in catalogue order. */
    private List<PqcRuleOrder.Candidate> candidates(PqcRuleInput input, Integer level, PqcReferences references) {
        List<PqcRuleCatalog.Entry> served = PqcRuleCatalog.servedFor(input.assetType());
        if (served.isEmpty()) {
            throw new IllegalStateException("No rule applies to an asset of type " + input.assetType());
        }
        List<PqcRuleOrder.Candidate> candidates = new ArrayList<>(served.size());
        if (PqcReferenceRules.decides(input.assetType())) {
            for (int position = 0; position < served.size(); position++) {
                candidates.add(referenceCandidate(served.get(position), position, input, level, references));
            }
            return candidates;
        }
        Reading reading = new Reading(input);
        for (int position = 0; position < served.size(); position++) {
            candidates.add(candidate(served.get(position), position, reading, level));
        }
        return candidates;
    }

    private static PqcRuleOrder.Candidate referenceCandidate(PqcRuleCatalog.Entry entry, int position,
            PqcRuleInput input, Integer level, PqcReferences references) {
        PqcDecision decision = PqcReferenceRules.candidate(entry.id(), input, level, references);
        if (decision != null) {
            return new PqcRuleOrder.Candidate(entry, position, decision, null, null);
        }
        return new PqcRuleOrder.Candidate(entry, position, null, PqcReferenceRules.notMatched(entry.id(), references),
                PqcReferenceRules
                        .evidence(PqcReferenceRules.READS_FIELDS.get(entry.id()), input, level, references, null));
    }

    private PqcRuleOrder.Candidate candidate(PqcRuleCatalog.Entry entry, int position, Reading reading, Integer level) {
        PqcDecision decision = decide(entry.id(), reading, level);
        if (decision != null) {
            return new PqcRuleOrder.Candidate(entry, position, decision, null, null);
        }
        return new PqcRuleOrder.Candidate(entry, position, null, NOT_MATCHED,
                projectEvidence(readsFieldsOf(entry), reading.input, level, entry.id()));
    }

    private PqcDecision decide(String ruleId, Reading reading, Integer level) {
        PqcRule table = tableRules.get(ruleId);
        if (table != null) {
            return table.matches().test(reading.input)
                    ? decision(table.verdict(), ruleId, table.reason(), table.readsFields(), reading.input, level)
                    : null;
        }
        CodedRule coded = codedRules.get(ruleId);
        if (coded == null) {
            throw new IllegalStateException("Catalogue entry " + ruleId + " has no rule");
        }
        return coded.apply(reading, level);
    }

    /** Every value the rules can read for this asset, in {@link PqcRules#INPUT_FIELDS} order; absent ones omitted. */
    public static Map<String, Object> inputsOf(PqcRuleInput input, Integer nistQuantumSecurityLevel,
            PqcReferences references) {
        Map<String, Object> inputs = projectEvidence(PqcRules.INPUT_FIELDS.subList(0, OWN_INPUT_FIELDS), input,
                nistQuantumSecurityLevel, "inputs");
        inputs.putAll(PqcReferenceRules.inputs(references));
        return inputs;
    }

    private List<String> readsFieldsOf(PqcRuleCatalog.Entry entry) {
        if (entry.readsFields() != null) {
            return entry.readsFields();
        }
        PqcRule table = tableRules.get(entry.id());
        if (table == null) {
            throw new IllegalStateException("Catalogue entry " + entry.id() + " is not in the table");
        }
        return table.readsFields();
    }

    // ---- The name's own decision, which the material size arms consult -----------------------------------------

    /**
     * What the asset's own name decides, with its declared size dropped: the coded rules alone, under the same order.
     * The size arms consult it before claiming a row, so a key and the algorithm of the same name cannot be served
     * opposite findings.
     */
    private PqcDecision nameDecision(PqcRuleInput input) {
        Reading reading = new Reading(input.withoutMaterialSize());
        List<PqcRuleCatalog.Entry> served = PqcRuleCatalog.servedFor(input.assetType());
        List<PqcRuleOrder.Candidate> candidates = new ArrayList<>(served.size());
        for (int position = 0; position < served.size(); position++) {
            PqcRuleCatalog.Entry entry = served.get(position);
            CodedRule coded = codedRules.get(entry.id());
            if (coded != null) {
                candidates.add(new PqcRuleOrder.Candidate(entry, position, coded.apply(reading, null), null, null));
            }
        }
        return PqcRuleOrder.select(candidates).decision();
    }

    /**
     * Whether the asset's own name is free of a weak-crypto finding, which gates only the weak size arm: a key under
     * the floor is weak whatever an {@code unknown} name leaves open, while a {@code notReady} name is the finding
     * itself, and a finding must reach the row whatever tier it was keyed on.
     */
    private boolean nameCarriesNoFinding(PqcRuleInput input) {
        return nameDecision(input).verdict() != PqcVerdict.NOT_READY;
    }

    /**
     * Whether the name leaves the key's strength to its size, which gates the ready and unsized arms: the name clears
     * as ready, or names no family at all. The carve-out is the common case -- nearly every secret key in the corpus
     * names no family and resolves to {@code FAMILY-UNRESOLVED}, so without it the arms would be empty. An ambiguous,
     * uninstantiated or unresolved-hybrid name is a question no key length answers, so the name decides it.
     */
    private boolean nameLeavesStrengthToSize(PqcRuleInput input) {
        PqcDecision byName = nameDecision(input);
        return byName.verdict() == PqcVerdict.READY || PqcRules.FAMILY_UNRESOLVED.equals(byName.ruleId());
    }

    // ---- What the coded rules read ------------------------------------------------------------------------------

    /**
     * Everything the coded rules read out of one input, derived once.
     *
     * <p>
     * A genuine hybrid is one whose components include a Shor-breakable half: the family rules do not apply to it,
     * because its stored family is whichever half the grammar elected, and its classical half is what the construction
     * is for and never the finding. The grammar also records a component list for a scheme whose parameter-set name
     * carries a hash token -- {@code SLH-DSA-SHAKE-256f} -- and that is no hybrid, so the family rules decide it.
     *
     * <p>
     * A family with no grammar rule survives into the variant as the asset's own name; when that is the only weak
     * token, the asset <em>is</em> the family and the family rules read it as one.
     */
    private final class Reading {

        private final PqcRuleInput input;
        private final List<String> hybridComponents;
        private final boolean genuineHybrid;
        private final Map<String, FamilyClass> weakTokens;
        private final boolean nameIsTheSoleWeakToken;
        private final String family;
        private final FamilyClass disposition;
        private final boolean construction;
        private final FamilyClass namedPrimitive;
        private final boolean nonKeyPrimitive;
        private final Set<Integer> admissibleParameterSets;
        private final boolean parameterSetUnregistered;
        private final Integer recordedSize;
        /** The input the coded rules record as evidence: the effective family and the genuine hybrid components. */
        private final PqcRuleInput evidence;

        private Reading(PqcRuleInput input) {
            this.input = input;
            String stored = ratifiedFamily(input.algorithmFamily());
            this.hybridComponents = hybridComponentsOf(input, stored);
            this.genuineHybrid = hybridComponents.stream().anyMatch(PqcEvaluator.this::isShorBreakable);
            this.weakTokens = weakSecondaryTokens(input);
            this.nameIsTheSoleWeakToken = input.algorithmFamily() == null && weakTokens.size() == 1
                    && weakTokens.containsKey(input.name());
            this.family = nameIsTheSoleWeakToken ? ratifiedFamily(input.name()) : stored;
            this.disposition = PqcFamilies.of(family);
            this.construction = PqcFamilies.isConstruction(family);
            this.namedPrimitive = construction ? namedPrimitive(input) : null;
            this.nonKeyPrimitive = input.primitive() != null
                    && PqcRules.NON_KEY_PRIMITIVES.contains(AsciiText.fold(input.primitive()));
            this.admissibleParameterSets = disposition == null || construction
                    ? null
                    : normalizer.admissibleParameterSets(input.name(), family);
            this.parameterSetUnregistered = admissibleParameterSets != null && input.parameterSet() != null
                    && !admissibleParameterSets.contains(input.parameterSet());
            this.recordedSize = recordedSizeBits(input, construction || nonKeyPrimitive || parameterSetUnregistered);
            PqcRuleInput withFamily = nameIsTheSoleWeakToken ? input.withAlgorithmFamily(family) : input;
            this.evidence = withFamily.withHybridComponents(genuineHybrid ? hybridComponents : List.of());
        }

        private boolean symmetric() {
            return disposition == FamilyClass.QUANTUM_RESISTANT_SYMMETRIC;
        }

        /** A primitive is its own strength; a construction's is its named primitive's, when it names a sound one. */
        private boolean instantiated() {
            return !construction || namedPrimitive == FamilyClass.QUANTUM_RESISTANT_SYMMETRIC;
        }

        private FamilyClass decisiveHybridComponent() {
            return hybridComponents
                    .stream()
                    .map(PqcEvaluator.this::dispositionOfComponent)
                    .filter(Objects::nonNull)
                    .filter(FamilyClass::isPostQuantum)
                    .min(FamilyClass.byHybridPrecedence())
                    .orElse(null);
        }
    }

    // ---- The coded rules ----------------------------------------------------------------------------------------

    /**
     * {@code HMAC-MD5} elects family {@code HMAC} and stores {@code md5} in the variant slot; {@code 3DES-CMAC} elects
     * {@code CMAC} and stores {@code 3des,des}. Reading the family alone answered {@code ready} for both, erasing the
     * finding the tokens were made identity-bearing to keep. Inside a hybrid the elected family counts too: the
     * {@code PBKDF1} that {@code PBKDF1-X25519-ML-KEM-768} elects appears in no secondary token.
     */
    private PqcDecision classicalLegacyComponent(Reading reading, Integer level) {
        boolean legacy = reading.weakTokens.containsValue(FamilyClass.CLASSICAL_LEGACY)
                || (reading.genuineHybrid && reading.disposition == FamilyClass.CLASSICAL_LEGACY);
        if (reading.nameIsTheSoleWeakToken || !legacy) {
            return null;
        }
        return decision(PqcVerdict.NOT_READY, PqcRules.CLASSICAL_LEGACY_COMPONENT,
                "A component named by this asset is already broken classically, so the construction inherits it",
                COMPONENT_FIELDS, reading.evidence, level);
    }

    /**
     * A hybrid's classical half is Shor-breakable by design -- that is what the construction is for -- so this rule
     * does not read a genuine hybrid's tokens; the hybrid rule decides it by its post-quantum component.
     */
    private PqcDecision classicalShorComponent(Reading reading, Integer level) {
        if (reading.genuineHybrid || reading.nameIsTheSoleWeakToken
                || !reading.weakTokens.containsValue(FamilyClass.SHOR_BREAKABLE)) {
            return null;
        }
        return decision(PqcVerdict.NOT_READY, PqcRules.CLASSICAL_SHOR_COMPONENT,
                "A component named by this asset rests on factorisation or a discrete logarithm, so the construction "
                        + "inherits its quantum vulnerability",
                COMPONENT_FIELDS, reading.evidence, level);
    }

    /**
     * A hybrid's readiness is its post-quantum component's, not the fact that it has one: {@code X25519-ML-KEM-768} is
     * ready, {@code X25519-Kyber768} is not, because bare Kyber is a superseded draft. Among several post-quantum
     * components {@link FamilyClass#byHybridPrecedence()} decides, so the answer does not depend on the order the name
     * spelt them. A broken digest beside the halves is the component rule's finding, which outranks this one.
     */
    private PqcDecision hybrid(Reading reading, Integer level) {
        if (!reading.genuineHybrid) {
            return null;
        }
        FamilyClass decisive = reading.decisiveHybridComponent();
        if (decisive == null) {
            return null;
        }
        String reason = decisive.verdict() == PqcVerdict.READY
                ? "A hybrid construction; its readiness is that of its post-quantum component"
                : "A hybrid construction whose post-quantum component is not standardised: " + decisive.reason();
        return decision(decisive.verdict(), PqcRules.HYBRID + "-" + decisive.ruleId(), reason, HYBRID_FIELDS,
                reading.evidence, level);
    }

    /** Recorded as hybrid, but no component resolves to a post-quantum family; the classical half must not decide. */
    private PqcDecision hybridUnresolved(Reading reading, Integer level) {
        if (!reading.genuineHybrid || reading.decisiveHybridComponent() != null) {
            return null;
        }
        return decision(PqcVerdict.UNKNOWN, PqcRules.HYBRID_UNRESOLVED,
                "A hybrid construction whose post-quantum component resolves to no ratified family", HYBRID_FIELDS,
                reading.evidence, level);
    }

    private PqcDecision familyUnresolved(Reading reading, Integer level) {
        if (reading.genuineHybrid || reading.disposition != null) {
            return null;
        }
        return decision(PqcVerdict.UNKNOWN, PqcRules.FAMILY_UNRESOLVED,
                "The recorded properties resolve to no ratified algorithm family, so no rule can classify it",
                List
                        .of(PqcRules.ASSET_TYPE, PqcRules.MATERIAL_TYPE, PqcRules.ALGORITHM_FAMILY, PqcRules.NAME,
                                PqcRules.VARIANT),
                reading.evidence, level);
    }

    /**
     * Every curve the tables ratify under GOST is a GOST R 34.10 curve, so a curve on an ambiguous family names the EC
     * signature scheme; the hash and the block ciphers carry none. Exact, not a heuristic: the curve column is
     * populated only from the ratified curve tables.
     */
    private PqcDecision classicalShor(Reading reading, Integer level) {
        boolean shorBreakable = reading.disposition == FamilyClass.SHOR_BREAKABLE
                || (reading.disposition == FamilyClass.FAMILY_AMBIGUOUS && reading.input.curve() != null);
        if (reading.genuineHybrid || !shorBreakable) {
            return null;
        }
        FamilyClass shor = FamilyClass.SHOR_BREAKABLE;
        return decision(shor.verdict(), shor.ruleId(), shor.reason(),
                List.of(PqcRules.ALGORITHM_FAMILY, PqcRules.CURVE, PqcRules.VARIANT), reading.evidence, level);
    }

    private PqcDecision familyAmbiguous(Reading reading, Integer level) {
        if (reading.genuineHybrid || reading.disposition != FamilyClass.FAMILY_AMBIGUOUS
                || reading.input.curve() != null) {
            return null;
        }
        FamilyClass ambiguous = FamilyClass.FAMILY_AMBIGUOUS;
        return decision(ambiguous.verdict(), ambiguous.ruleId(), ambiguous.reason(), FAMILY_FIELDS, reading.evidence,
                level);
    }

    private PqcDecision ambiguousPrimitive(Reading reading, Integer level) {
        if (reading.genuineHybrid || !reading.symmetric() || !reading.construction
                || reading.namedPrimitive != FamilyClass.FAMILY_AMBIGUOUS) {
            return null;
        }
        return decision(PqcVerdict.UNKNOWN, PqcRules.FAMILY_AMBIGUOUS_COMPONENT,
                "A construction built on a primitive whose family covers both a classically broken and an unbroken "
                        + "member, and the recorded properties do not say which",
                FAMILY_FIELDS, reading.evidence, level);
    }

    private PqcDecision constructionUninstantiated(Reading reading, Integer level) {
        if (reading.genuineHybrid || !reading.symmetric() || !reading.construction || reading.namedPrimitive != null) {
            return null;
        }
        return decision(PqcVerdict.UNKNOWN, PqcRules.CONSTRUCTION_UNINSTANTIATED,
                "A construction whose strength is that of the primitive it is built on, which this record does not "
                        + "name",
                List.of(PqcRules.ALGORITHM_FAMILY, PqcRules.VARIANT, PqcRules.PARAMETER_SET), reading.evidence, level);
    }

    /**
     * There is no 64-bit AES and no ML-KEM-1000: a parameter set outside the family's registry enumeration is not a
     * weak instantiation but a record of something that does not exist, so no strength rule reads the number.
     */
    private PqcDecision parameterSetUnregistered(Reading reading, Integer level) {
        if (reading.genuineHybrid || !reading.parameterSetUnregistered) {
            return null;
        }
        String admitted = new TreeSet<>(reading.admissibleParameterSets)
                .stream()
                .map(String::valueOf)
                .collect(Collectors.joining(", "));
        return decision(PqcVerdict.UNKNOWN, PqcRules.PARAMETER_SET_UNREGISTERED,
                "The recorded parameter set is not one the " + reading.family + " family defines; the registry admits "
                        + admitted,
                List.of(PqcRules.ALGORITHM_FAMILY, PqcRules.PARAMETER_SET, PqcRules.VARIANT), reading.evidence, level);
    }

    private PqcDecision symmetricUndersized(Reading reading, Integer level) {
        if (reading.genuineHybrid || !reading.symmetric() || !reading.instantiated() || reading.recordedSize == null
                || reading.recordedSize >= PqcRules.MIN_SYMMETRIC_KEY_BITS) {
            return null;
        }
        return decision(PqcVerdict.NOT_READY, PqcRules.SYMMETRIC_UNDERSIZED,
                "A symmetric or hash-based primitive whose recorded size is below " + PqcRules.MIN_SYMMETRIC_KEY_BITS
                        + " bits, so Grover's algorithm leaves it with no adequate strength",
                sizeEvidence(reading.input, reading.construction), reading.evidence, level);
    }

    /**
     * Family membership is not a strength claim: a construction cannot make one without naming its primitive, a sized
     * primitive cannot make one below the floor, and a parameter set the family does not define vouches for nothing. A
     * KDF, DRBG, MAC or XOF primitive's parameter set is an output or tag length, so it is not read as a size.
     */
    private PqcDecision symmetricReady(Reading reading, Integer level) {
        if (reading.genuineHybrid || !reading.symmetric() || !reading.instantiated() || reading.parameterSetUnregistered
                || (reading.recordedSize != null && reading.recordedSize < PqcRules.MIN_SYMMETRIC_KEY_BITS)) {
            return null;
        }
        FamilyClass ready = FamilyClass.QUANTUM_RESISTANT_SYMMETRIC;
        if (reading.recordedSize != null) {
            return decision(ready.verdict(), ready.ruleId(), ready.reason(),
                    sizeEvidence(reading.input, reading.construction), reading.evidence, level);
        }
        if (reading.nonKeyPrimitive) {
            return decision(ready.verdict(), ready.ruleId(),
                    reading.family + " is a " + AsciiText.fold(reading.input.primitive())
                            + " construction over a symmetric or hash-based family: its parameter set is an output "
                            + "or tag length rather than a key size, and no quantum algorithm breaks the family "
                            + "outright",
                    List.of(PqcRules.ALGORITHM_FAMILY, PqcRules.PRIMITIVE, PqcRules.VARIANT), reading.evidence, level);
        }
        return decision(ready.verdict(), ready.ruleId(), ready.reason(), FAMILY_FIELDS, reading.evidence, level);
    }

    /**
     * The LMS grammar keys LM-OTS, LMS and HSS-LMS alike and keeps the {@code ots} and {@code hss} discriminators in
     * the residue on purpose: key reuse is what tells a one-time signature from the many-time scheme built over it.
     */
    private PqcDecision oneTimeSignature(Reading reading, Integer level) {
        if (reading.genuineHybrid || reading.disposition != FamilyClass.PQC_STANDARDIZED
                || !STATEFUL_HASH_SIGNATURES.contains(reading.family)
                || secondaryTokens(reading.input).stream().noneMatch(token -> token.contains(ONE_TIME_SIGNATURE))) {
            return null;
        }
        return decision(PqcVerdict.UNKNOWN, PqcRules.ONE_TIME_SIGNATURE,
                "A one-time signature scheme, which SP 800-208 approves only as a component within LMS or XMSS and "
                        + "not on its own, so the family alone cannot affirm it",
                FAMILY_FIELDS, reading.evidence, level);
    }

    /** A family's own disposition. A ready one vouches for nothing when the parameter set is not the family's. */
    private PqcDecision familyDisposition(Reading reading, FamilyClass disposition, Integer level) {
        if (reading.genuineHybrid || reading.disposition != disposition
                || (disposition.verdict() == PqcVerdict.READY && reading.parameterSetUnregistered)) {
            return null;
        }
        return decision(disposition.verdict(), disposition.ruleId(), disposition.reason(), FAMILY_FIELDS,
                reading.evidence, level);
    }

    // ---- What the name carries ----------------------------------------------------------------------------------

    /**
     * The hybrid components the grammar recorded, widened by the secondary tokens.
     *
     * <p>
     * {@code AssetNormalizer.hybridComponents} tests membership against its own {@code PQC_FAMILIES}, which holds 25
     * tokens where the ratified tables name 33 pseudo-families. So {@code X25519-HAWK-512} recorded no components,
     * elected its classical half and read {@code notReady} on that half alone. The ratified tables answer for all 33.
     *
     * <p>
     * A name that alternates between schemes records no components on either path, so its classical half decides the
     * row through the component rules.
     */
    private List<String> hybridComponentsOf(PqcRuleInput input, String family) {
        if (!input.hybridComponents().isEmpty()) {
            return input.hybridComponents();
        }
        if (PqcFamilies.of(family) != FamilyClass.SHOR_BREAKABLE || normalizer.namesAnAlternation(input.name())) {
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

    private boolean isShorBreakable(String component) {
        return dispositionOfComponent(component) == FamilyClass.SHOR_BREAKABLE;
    }

    private FamilyClass dispositionOfComponent(String component) {
        return PqcFamilies.of(ratifiedFamily(FAMILY_SIZE_SUFFIX.matcher(component).replaceFirst("")));
    }

    /**
     * The disposition of the primitive a construction's secondary tokens name, or {@code null} when they name none.
     * Another construction does not count, since the pair says no more than either half, and a bare parameter set does
     * not either. An ambiguous primitive outranks an unbroken one: a construction cannot be vouched for over a part
     * that may be the broken member.
     */
    private FamilyClass namedPrimitive(PqcRuleInput input) {
        FamilyClass named = null;
        for (String token : secondaryTokens(input)) {
            String family = ratifiedFamilyOfToken(token);
            FamilyClass disposition = PqcFamilies.of(family);
            if (disposition == FamilyClass.FAMILY_AMBIGUOUS) {
                return disposition;
            }
            if (disposition == FamilyClass.QUANTUM_RESISTANT_SYMMETRIC && !PqcFamilies.isConstruction(family)) {
                named = disposition;
            }
        }
        return named;
    }

    /**
     * The size the row records, from whichever slot carries it, and only inside the ratified size band.
     *
     * <p>
     * {@code materialSize} counts only on a material row. A producer bug stamps the material block onto algorithms too,
     * and there the row's own size is its parameter set -- a strayed size would otherwise decide {@code AES-64} ready
     * and {@code AES-256} undersized. When a key's name spells a size too, the smaller decides: a declared size must
     * not clear a key its own algorithm name fails.
     *
     * @param parameterSetIsNotASize a construction's digest or tag length, a non-key primitive's output length, or a
     * number the family does not define
     */
    private Integer recordedSizeBits(PqcRuleInput input, boolean parameterSetIsNotASize) {
        Integer named = parameterSetIsNotASize ? null : withinRatifiedSizeBand(input.parameterSet());
        if (input.assetType() == CryptographicAssetType.RELATED_CRYPTO_MATERIAL && input.materialSize() != null) {
            return named == null ? input.materialSize() : Math.min(input.materialSize(), named);
        }
        return named;
    }

    /** The slots {@link #recordedSizeBits} reads for this row, so the evidence names only the size that decided. */
    private static List<String> sizeEvidence(PqcRuleInput input, boolean construction) {
        List<String> fields = new ArrayList<>(List.of(PqcRules.ALGORITHM_FAMILY));
        if (!construction) {
            fields.add(PqcRules.PARAMETER_SET);
        }
        if (input.assetType() == CryptographicAssetType.RELATED_CRYPTO_MATERIAL) {
            fields.add(PqcRules.MATERIAL_SIZE);
        }
        fields.add(PqcRules.VARIANT);
        return List.copyOf(fields);
    }

    /**
     * Below the floor bits and bytes cannot be told apart: {@code 32} is AES-256 in bytes and a broken key in bits, and
     * the rules must not guess. Above the ceiling a number is a cost or round count rather than a size.
     */
    private Integer withinRatifiedSizeBand(Integer bits) {
        return bits != null && bits >= normalizer.tables().sizeMin() && bits <= normalizer.tables().sizeMax()
                ? bits
                : null;
    }

    /**
     * Any spelling onto the ratified one, and not optional: the column is case-folded while {@code AssetNormalizer}
     * compares family tokens case-sensitively, so passing a folded {@code x-wing} straight back took the non-hybrid
     * path and re-derived different components.
     */
    private String ratifiedFamily(String anySpelling) {
        return normalizer.tables().familyToken(anySpelling);
    }

    private FamilyClass dispositionOfToken(String token) {
        return PqcFamilies.of(ratifiedFamilyOfToken(token));
    }

    /**
     * A component token onto its ratified family, whole spelling first.
     *
     * <p>
     * The size suffix is stripped only as a fallback, because several families carry a digit that is part of the name:
     * stripping first turns {@code sha-1} into {@code sha} and {@code sha-2} into {@code sha}, which resolve to nothing
     * -- so {@code HMAC-SHA1} read {@code ready}. The normalizer documents the same trap on its own token folding.
     */
    private String ratifiedFamilyOfToken(String token) {
        String whole = ratifiedFamily(token);
        return PqcFamilies.of(whole) != null
                ? whole
                : ratifiedFamily(FAMILY_SIZE_SUFFIX.matcher(token).replaceFirst(""));
    }

    // ---- The input shape ------------------------------------------------------------------------------------------

    /**
     * {@code hybridComponents} is re-derived, not read: it is out-of-key by construction and has no column.
     *
     * <p>
     * A material row is judged by its own name and its stored properties, never by its family, size, curve or primitive
     * columns. Those hold what {@code CryptoAssetIdentity} copied from the algorithm the row references and the key's
     * own declared {@code size}: filter slots, not evidence. Read here, half an algorithm decided the key -- the family
     * of {@code X25519-Kyber768} is {@code ECDH} and its hybrid components have no column, so a shared secret under it
     * read {@code CLASSICAL-SHOR} on the classical half alone -- and a referenced size outranked the one the key's own
     * name spells. So the family and the size come from the name. Confined to material: on an algorithm row a null
     * family is the normalizer's decision, a cipher suite above all, and stands.
     */
    public PqcRuleInput fromStoredRow(CryptoAssetIdentityFields fields, JsonNode mergedCryptoProperties) {
        boolean material = fields.assetType() == CryptographicAssetType.RELATED_CRYPTO_MATERIAL;
        String family = material
                ? ratifiedFamily(normalizer.familyFromName(fields.name()))
                : ratifiedFamily(fields.algorithmFamily());
        Integer parameterSet = material ? sizeFromName(fields.name(), family) : parameterSet(fields.parameterSet());
        String curve = material ? null : fields.curve();
        String primitive = material ? null : fields.primitive();
        String secondary = normalizer.secondaryTokens(fields.name(), family);
        List<String> hybrid = normalizer.hybridComponents(fields.name(), family, secondary);
        return new PqcRuleInput(fields.assetType(), family, parameterSet, curve, fields.mode(), fields.padding(),
                variantOf(fields, secondary), fields.name(), hybrid, materialType(mergedCryptoProperties),
                materialSize(mergedCryptoProperties), primitive);
    }

    /**
     * Related material takes its variant from the secondary tokens of its name, because the weak-component doctrine
     * reads that field and the material tier derives none of its own.
     */
    private static String variantOf(CryptoAssetIdentityFields fields, String secondaryTokens) {
        if (fields.variant() != null || fields.assetType() != CryptographicAssetType.RELATED_CRYPTO_MATERIAL) {
            return fields.variant();
        }
        return secondaryTokens == null || secondaryTokens.isEmpty() ? null : secondaryTokens;
    }

    private Integer sizeFromName(String name, String family) {
        Integer spelled = normalizer.sizeTheFamilySpells(name, family);
        return spelled != null ? spelled : normalizer.intrinsicParameterSet(name);
    }

    /**
     * The normalizer's routing vocabulary onto the column's enum. The unroutable value remains the column's answer for
     * a component the normalizer routes nowhere; ingest no longer stores one.
     */
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
     * camelCase these vocabularies. {@code unknown} is kept as a value of the material-type vocabulary; this reader
     * takes it as "the producer said nothing" rather than a fourth arm of the material partition.
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
     * count are absent rather than republished as a strength.
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
        return withinRatifiedSizeBand(size.intValue());
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
            case PqcRules.PRIMITIVE -> input.primitive();
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
