package com.otilm.core.cbom.asset.identity;

import com.fasterxml.jackson.databind.JsonNode;
import java.math.BigDecimal;
import java.math.BigInteger;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.TreeSet;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * The whole normalization pipeline, as one pure function from a component to its typed slots.
 *
 * <p>
 * Each slot is derived by its own step, and the order is not arbitrary: the family decides whether a name may
 * contribute a curve, the parameter set decides which digit runs the variant may keep, and the mode decides which token
 * the variant must not repeat. A digit run consumed by one slot must never be consumed again by another.
 *
 * <p>
 * The recurring principle, stated once here because it decides a dozen rules below: <b>every producer-supplied
 * "authoritative" identifier in a CBOM has been observed fabricated in real data.</b> OIDs (an {@code id-sha3-384} arc
 * on an asset named SHA-384), certificate fingerprints (one placeholder digest on a revoked and an active certificate),
 * cipher-suite codes (one placeholder stamped on three different suites), and {@code algorithmFamily} itself. So every
 * such field is <em>corroborated</em> rather than trusted, and loses when it contradicts something better supported.
 */
public record AssetNormalizer(IdentityTables tables) {

    /**
     * Producers spell the asset type inconsistently. One real document emits {@code relatedCryptoMaterial} in camelCase
     * where the schema says {@code related-crypto-material}; routing on the raw string sent it to the unknown-type
     * backstop and gave it a key no other producer could ever match.
     */
    private static final Map<String, String> ASSET_TYPES = assetTypes();

    private static Map<String, String> assetTypes() {
        Map<String, String> types = new LinkedHashMap<>();
        for (String canonical : List
                .of(CbomNames.ASSET_TYPE_ALGORITHM, CbomNames.ASSET_TYPE_CERTIFICATE, CbomNames.ASSET_TYPE_PROTOCOL,
                        CbomNames.ASSET_TYPE_RELATED_CRYPTO_MATERIAL)) {
            types.put(canonical, canonical);
        }
        for (String misspelling : List
                .of("relatedcryptomaterial", "related_crypto_material", "relatedcryptographicmaterial", "material")) {
            types.put(misspelling, CbomNames.ASSET_TYPE_RELATED_CRYPTO_MATERIAL);
        }
        return Map.copyOf(types);
    }

    /**
     * The only registered hybrid token the tables carry. A hybrid names two constructions, so several grammar rules
     * match its name and the ordered match elects whichever appears first -- which made the family depend on how the
     * producer spelled the separator. Listed here rather than inferred, because "is this token a hybrid" is not
     * derivable from the registry: the registry has no hybrid concept at all.
     */
    private static final Set<String> HYBRID_FAMILIES = Set.of("X-Wing");

    /**
     * The longest primitive worth storing. The CycloneDX vocabulary's longest member is well inside it, so this bounds
     * malformed producer text without truncating anything real.
     */
    private static final int MAX_PRIMITIVE_LENGTH = 64;

    /**
     * The longest producer string this normalizer will read, matching {@code ck_crypto_asset_name_length} and the
     * writer's own pre-check on the name. Held as a constant here because normalization runs long before the write. The
     * algorithm-property fields and the {@code oid} are held to the same bound -- {@link #boundedText} says why one
     * bound is enough, and which producer strings it does not cover.
     */
    private static final int MAX_NORMALIZABLE_LENGTH = 1024;

    /**
     * Post-quantum families, standardized and pre-standard alike, folded for comparison. Used <em>only</em> to
     * recognize a hybrid construction for out-of-key provenance; no identity slot reads this set.
     */
    private static final Set<String> PQC_FAMILIES = Set
            .of("ml-kem", "ml-dsa", "slh-dsa", "fn-dsa", "xmss", "lms", "kyber", "dilithium", "falcon", "sphincs+",
                    "classic mceliece", "frodokem", "bike", "hqc", "ntru", "ntru-prime", "sike", "sidh", "gemss",
                    "cross", "mqom", "snova", "uov", "mayo", "x-wing");

    /**
     * Functions that determine a primitive unambiguously. {@code encrypt}/{@code decrypt} and {@code keygen} are
     * deliberately absent: they are consistent with several primitives, so they defer to the family default rather than
     * guess.
     */
    private static final Map<String, String> FUNCTION_PRIMITIVE = Map
            .of("sign", "signature", "verify", "signature", "encapsulate", "kem", "decapsulate", "kem", "digest",
                    "hash", "tag", "mac", "keyderive", "kdf");

    /**
     * Functions that genuinely conflict with a signing or KEM reading. Their presence makes the set ambiguous, because
     * an asset declaring {@code [decrypt, encrypt, sign, verify]} says nothing decisive and must fall to the family
     * default rather than being read as {@code signature} and split from a sibling declaring {@code pke}.
     */
    private static final Set<String> CONFLICTING_FUNCTIONS = Set
            .of("encrypt", "decrypt", "wrap", "unwrap", "keywrap", "other", "unknown");

    /**
     * Functions that accompany any primitive and carry no signal either way. Ignoring them rather than treating them as
     * ambiguity is what keeps {@code [keygen, sign, verify]} readable as {@code signature}.
     */
    private static final Set<String> NEUTRAL_FUNCTIONS = Set.of("keygen", "generate", "keycheck", "store", "export");

    /** Modes that make a construction authenticated encryption. */
    private static final Set<String> AE_MODES = Set.of("GCM", "CCM", "POLY1305", "SIV", "OCB", "EAX");

    /**
     * Only these three fold. A {@code hash}, {@code signature} or {@code kdf} primitive is never turned into {@code ae}
     * by a mode token appearing in the name.
     */
    private static final Set<String> AE_FOLDABLE = Set.of("block-cipher", "stream-cipher", "ae");

    /**
     * Families whose {@code parameterSet} means a KEY size, so a digest length in the name can never be it: an
     * "RSA-256" key is absurd, and {@code SHA512withRSA} was storing 512. Scoped to the RSA family on purpose -- for a
     * hash or a MAC the digest length IS the parameter, and for ECDSA it usually coincides with the curve size, so
     * stripping it there would discard real information to fix a coincidence. The bare pseudo-family is in scope: it is
     * what a JCA transformation such as {@code RSA/ECB/OAEPWithSHA-256AndMGF1Padding} elects, and the scheme prefixes
     * alone let exactly that name store a 256-bit key.
     */
    private static final List<String> KEY_SIZE_FAMILIES = List.of("RSA");

    /**
     * A digest token and the length it names, in every spelling the RSA schemes are written with. The left guard admits
     * the JCA infix -- {@code RSA/ECB/OAEPWithSHA-256AndMGF1Padding} names SHA-256 after a letter -- and the optional
     * family digit admits RFC 8332's {@code rsa-sha2-256} and the {@code SHA3-256} spelling; without either, the rule
     * the Javadoc of {@link #KEY_SIZE_FAMILIES} states was true only for the hyphenated {@code SHA256withRSA} shape,
     * and the commonest JCA spelling stored a 256-bit RSA key.
     */
    private static final Pattern DIGEST_IN_NAME = Pattern
            .compile("(?:(?<![A-Z0-9])|(?<=with))(?:SHA|MD)-?(?:[23][-_/]?)?(\\d{3,4})(?!\\d)",
                    Pattern.CASE_INSENSITIVE);

    /**
     * The separators a producer's {@code assetType} spelling may carry, over the reference whitespace set.
     *
     * <p>
     * {@code [\s_]+} was Java's {@code \s}, which does not treat U+0085, U+00A0, U+2007 or U+202F as whitespace -- so
     * {@code related crypto material} written with a no-break space missed this key, missed the plain
     * {@code toLowerCase} fallback beside it, and routed to the unroutable tier, where a material asset keys as a raw
     * backstop instead of through the material chain. A fifth site for core#2165 item 18, found by review after the
     * item's own list was closed.
     *
     * <p>
     * {@link AsciiText#collapseWhitespace} rather than {@link AsciiText#lookupKey}: the lookup key also folds {@code -}
     * and {@code /}, which would widen routing past whitespace and could move a key on a spelling {@code ASSET_TYPES}
     * does not carry. Widening exactly one thing is what makes this a repair.
     */
    private static final Pattern ASSET_TYPE_SEPARATORS = Pattern.compile("[\\s_]+");

    /** The {@code -<digits>} parameter-set size {@link #sizedFamilyToken} appends to a family token. */
    private static final Pattern FAMILY_SIZE_SUFFIX = Pattern.compile("-\\d+$");

    /**
     * The word guards a token spelling is matched with. A guard on both sides is what stops {@code dsa} matching inside
     * {@code ECDSA}; spelled once so a rule cannot be built with one side missing.
     */
    private static final String LEFT_WORD_GUARD = "(?<![A-Za-z0-9])";

    private static final String RIGHT_WORD_GUARD = "(?![A-Za-z0-9])";

    private static final Pattern DIGITS = Pattern.compile("\\d+");

    private static final Pattern DIGIT_RUN_2_TO_5 = Pattern.compile("\\d{2,5}");

    private static final Pattern SEPARATORS = Pattern.compile("[-_\\s]+");

    private static final Pattern TRUNCATION = Pattern.compile("[/-](\\d{2,5})\\s*$");

    private static final Pattern LEVEL_MARKER = Pattern
            .compile("(?<![A-Za-z0-9])([A-Za-z]{1,3}\\d{1,4})(?![A-Za-z0-9])");

    private static final Pattern PARAMETER_LEVEL = Pattern.compile("[-_/](\\d{1,4})\\s*$");

    private static final Pattern NON_LETTERS = Pattern.compile("[^A-Za-z]");

    private static final Pattern NON_ALPHANUMERIC = Pattern.compile("[^A-Za-z0-9]");

    /**
     * The word JCA glues to a padding token in a transformation string. Admitted into the name match as an optional
     * suffix because the right word guard alone refused it: {@code AES/CBC/PKCS5Padding} -- the commonest JCA spelling
     * -- derived no padding while {@code AES/CBC/PKCS5} did, and the two split. {@code OAEPWithSHA-256AndMGF1Padding}
     * still derives none: the token there is followed by {@code With}, not by this word.
     */
    private static final String JCA_PADDING_WORD = "PADDING";

    private static final String JCA_PADDING_SUFFIX = "(?:" + JCA_PADDING_WORD + ")?";

    private static final Pattern LOCAL_SIZE_RUN = Pattern.compile("[^A-Za-z0-9]*[A-Za-z]*[-_/]?(\\d{1,5})");

    private static final Pattern ADJACENT_SIZE_RUN = Pattern.compile("[-_/]?(\\d{2,5})");

    /**
     * The separators producers use for "either of these", and nothing around them.
     *
     * <p>
     * The surrounding {@code \s*} this carried made the split <b>quadratic</b> on producer-supplied text: every start
     * position scanned the whole remaining whitespace run before failing on the alternation, so 16 000 spaces in an
     * {@code ellipticCurve} field took 6.8s and a megabyte took hours. At the time only the component NAME was
     * length-capped and the curve channels were not, so the field was an uncapped stall in ingest. Matching the
     * separator alone is linear -- a megabyte now costs 31ms -- and costs nothing, because {@code canonicalCurve}
     * strips each part before it looks anything up. {@link #boundedText} has since closed the other half: the pattern
     * bounds the work per character, the cap bounds the characters.
     */
    private static final Pattern CURVE_ALTERNATIVES = Pattern.compile("[/,+]|\\bor\\b|\\band\\b");

    /** The ratified tables this pipeline reads. Exposed so the identity chain resolves names through the same data. */
    @Override
    public IdentityTables tables() {
        return tables;
    }

    /**
     * Normalizes one component, returning its typed slots and the redaction that produced the payload they were read
     * from.
     *
     * <p>
     * Redaction runs first and unconditionally, so no later step -- and no caller -- ever observes key material.
     *
     * <p>
     * The algorithm slots are derived only for a component routed as an algorithm. Every one of them is read out of the
     * name and {@code algorithmProperties}, so without the gate a certificate named {@code server-rsa-2048.pem} carried
     * RSA, 2048 and a signature primitive, and a password named for the DES vault it opens carried DES and a block
     * cipher -- into columns that are stored, indexed and offered as filters. The strand's protocol arcs state the
     * rule: family derivation runs only on {@code assetType == algorithm}. The OID is not one of those slots. It is the
     * asset's own identifier, protocol assets carry one in real documents, and it is recorded for every type.
     */
    public Result normalize(JsonNode component) {
        MaterialRedaction redaction = MaterialRedaction.of(component.get("cryptoProperties"));
        JsonNode properties = redaction.keyedPayload();

        // Routed on cryptoProperties.assetType alone, never on the component's own type and never on which
        // properties block happens to be present. A producer bug once stamped relatedCryptoMaterialProperties onto
        // algorithms and certificates; a presence-based router would have pulled those into the wrong chain and
        // minted phantom material rows from the empty blocks it left behind.
        //
        // The name is read raw because past the bound it refuses the component, where every other field reads as
        // absent, and the bounded reader would have turned the refusal into a nameless row. The asset type is read
        // raw because it is the router, not a slot: bounded, one character past the limit cost a material row its
        // whole chain and keyed it on the unknown-type backstop, the outcome ASSET_TYPE_SEPARATORS was added to
        // close for whitespace, reached through length instead. Routing is a closed four-value decision that does
        // linear work and no unbounded work follows it, so the bound bought nothing there.
        JsonNode name = component.get("name");
        String componentName = name != null && name.isTextual() ? name.textValue() : null;
        requireNormalizableName(componentName);
        JsonNode assetType = properties.get("assetType");
        NormalizedAsset norm = new NormalizedAsset(
                normalizeAssetType(assetType != null && assetType.isTextual() ? assetType.textValue() : null),
                componentName);

        recordOid(norm, boundedText(norm, properties, "oid"));
        if (CbomNames.ASSET_TYPE_ALGORITHM.equals(norm.assetType())) {
            deriveAlgorithmSlots(norm, objectOrEmpty(properties.get("algorithmProperties")));
        }
        return new Result(norm, redaction);
    }

    /** The normalized asset and the redaction whose payload every later step must read. */
    public record Result(NormalizedAsset asset, MaterialRedaction redaction) {
    }

    /**
     * Family, size, curve, mode, padding, primitive and variant, in the order the class documentation fixes: each
     * step's answer decides what the next may still read out of the name.
     */
    private void deriveAlgorithmSlots(NormalizedAsset norm, JsonNode algorithm) {
        IdentityTables.OidEntry enrichment = deriveFamily(norm, algorithm);
        deriveParameterSet(norm, algorithm, enrichment);
        deriveCurve(norm, algorithm, enrichment);
        deriveMode(norm, algorithm, enrichment);
        derivePadding(norm, algorithm);
        derivePrimitive(norm, algorithm);
        foldAuthenticatedEncryption(norm);

        List<String> dropped = new ArrayList<>();
        String residue = variantResidue(norm.name(), norm.parameterSet(), norm.mode(), norm.family(),
                norm.paddingFromName(), dropped);
        if (!dropped.isEmpty()) {
            norm
                    .note("L7: name residue " + dropped
                            + " is outside the closed construction vocabulary and IS part of "
                            + "this row's identity, so a sibling spelling without it keys separately");
        }
        String secondary = secondaryTokens(norm.name(), norm.family());
        String variant = joinNonEmpty("+", residue, secondary);
        norm.setVariant(variant == null || variant.isEmpty() ? null : variant);
        norm.addHybridComponents(hybridComponents(norm.family(), secondary));
        if (!norm.hybridComponents().isEmpty()) {
            norm
                    .note("L10: hybrid construction (" + String.join(" + ", norm.hybridComponents())
                            + "); the stored family " + norm.family()
                            + " is one half of it, because the registry has no " + "hybrid token");
        }
    }

    /**
     * Refuses a name too long to store before it is normalized.
     *
     * <p>
     * Several derivations below are quadratic in the name length -- the grammar rules backtrack, and the residue pass
     * runs a full replace per family -- so a handful of long-named components in one third-party document is a CPU
     * stall on the ingest path. Measured before the bound: 203 ms at 14 000 characters, 34 678 ms at 224 000.
     *
     * <p>
     * The bound is the storage bound, so nothing refused here could have been written anyway: the column's CHECK and
     * the writer's pre-check both stop at the same length. Refusing costs the component its row and reports it as a
     * skip, which is what the walker does with anything it cannot key -- and a skip names the failure class only, never
     * the name that caused it.
     */
    private static void requireNormalizableName(String name) {
        if (exceedsNormalizableLength(name)) {
            throw new IllegalArgumentException("A component name exceeds the storable length");
        }
    }

    private static boolean exceedsNormalizableLength(String value) {
        return value != null && value.codePointCount(0, value.length()) > MAX_NORMALIZABLE_LENGTH;
    }

    /** The producer's arc as written and as reduced, with a note when the two differ by more than spelling. */
    private void recordOid(NormalizedAsset norm, String rawOid) {
        norm.setRawOid(rawOid);
        norm.setOid(normalizeOid(rawOid));
        if (rawOid != null && norm.oid() == null) {
            norm.note("oid " + rawOid + " is not a usable dotted arc");
        }
    }

    /** Routes the producer's spelling onto one of the four known types, or {@code null} for the unroutable tier. */
    public String normalizeAssetType(String raw) {
        if (raw == null || AsciiText.isBlank(raw)) {
            return null;
        }
        String stripped = AsciiText.collapseWhitespace(AsciiText.strip(raw));
        String key = ASSET_TYPE_SEPARATORS.matcher(stripped).replaceAll("").toLowerCase(Locale.ROOT);
        String routed = ASSET_TYPES.get(key);
        return routed != null ? routed : ASSET_TYPES.get(stripped.toLowerCase(Locale.ROOT));
    }

    /**
     * Reduces a producer's {@code oid} to a bare dotted arc, or {@code null}.
     *
     * <p>
     * Neither the 1.6 nor the 1.7 schema puts a pattern on this field, so every junk value seen in the wild is
     * schema-valid: {@code ietf-rfc8439}, {@code n/a}, {@code 0.0.0.0}, and one producer's composite
     * {@code nistp256@1.2.840.10045.3.1.7}, which comes from assigning the OID from a parameter-set identifier.
     */
    public String normalizeOid(String raw) {
        if (raw == null || tables.isSentinel(raw)) {
            return null;
        }
        String text = AsciiText.strip(raw);
        for (String prefix : List.of("urn:oid:", "oid:")) {
            if (AsciiText.fold(text).startsWith(prefix)) {
                text = AsciiText.strip(text.substring(prefix.length()));
                break;
            }
        }
        int composite = text.lastIndexOf('@');
        if (composite >= 0) {
            text = AsciiText.strip(text.substring(composite + 1));
        }
        while (text.endsWith(".")) {
            text = text.substring(0, text.length() - 1);
        }
        if (!AsciiText.isDottedDigits(text, 2)) {
            return null;
        }
        return text;
    }

    /**
     * Longest dot-boundary prefix match, with heterogeneous containers blocked.
     *
     * <p>
     * Walking down from the full arc -- rather than scanning the table -- makes the dot-boundary rule structural:
     * {@code 1.2.840.113549.1.1} can never match the query {@code 1.2.840.113549.1.10}, because the walk only ever
     * tests whole arcs. A blocked prefix terminates the walk with <em>no family</em>, which is a defined answer:
     * bare-arc tolerance is sound on a homogeneous subtree and unsound on a mixed one, where a truncated arc would
     * silently turn SHA3-512 into SHA-2.
     */
    public IdentityTables.OidEntry oidLookup(String oid) {
        if (oid == null || oid.isEmpty()) {
            return null;
        }
        String[] arcs = oid.split("\\.");
        for (int length = arcs.length; length > 1; length--) {
            String candidate = String.join(".", List.of(arcs).subList(0, length));
            if (tables.oidBlockedPrefixes().contains(candidate)) {
                return null;
            }
            IdentityTables.OidEntry entry = tables.oidToFamily().get(candidate);
            if (entry != null) {
                return entry.matchedAt(candidate, List.of(arcs).subList(length, arcs.length));
            }
        }
        return null;
    }

    /**
     * Ordered, word-guarded token match; first rule wins.
     *
     * <p>
     * One exception: a hybrid token recognized in the separator-stripped name wins over the ordered match.
     * {@code X25519MLKEM768} elected {@code X-Wing} while {@code X25519-ML-KEM-768} elected {@code ECDH} -- one
     * construction, two families, decided by a hyphen. Stripping separators is confined to this test: doing it before
     * the general match would break every word guard the grammar depends on, since {@code design} would read as
     * {@code DES}.
     */
    public String familyFromName(String name) {
        if (name == null || AsciiText.isBlank(name)) {
            return null;
        }
        String ordered = null;
        for (IdentityTables.GrammarRule rule : tables.nameGrammar()) {
            if (rule.strict().matcher(name).find()) {
                ordered = rule.family();
                break;
            }
        }
        if (ordered == null || !HYBRID_FAMILIES.contains(ordered)) {
            String glued = SEPARATORS.matcher(name).replaceAll("");
            if (!glued.equals(name)) {
                for (IdentityTables.GrammarRule rule : tables.nameGrammar()) {
                    if (HYBRID_FAMILIES.contains(rule.family()) && rule.strict().matcher(glued).find()) {
                        return rule.family();
                    }
                }
            }
        }
        return ordered;
    }

    /**
     * True when the name denotes a cipher SUITE rather than a single algorithm.
     *
     * <p>
     * Reducing a suite to one of its component ciphers throws away the key exchange and the authentication: measured on
     * unseen data, {@code TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256} and {@code TLS_ECDHE_RSA_WITH_ARIA_128_GCM_SHA256}
     * both reduced to their bulk cipher, and 33 groups of genuinely different suites collapsed. A suite therefore
     * derives NO family and is keyed on its full normalized name.
     */
    public boolean isCipherSuiteName(String name) {
        if (name == null || AsciiText.isBlank(name)) {
            return false;
        }
        String stripped = AsciiText.strip(name);
        return tables.cipherSuitePatterns().stream().anyMatch(pattern -> pattern.matcher(stripped).find());
    }

    /** The constructions a hybrid name names, when it names both kinds. Out-of-key by construction. */
    public List<String> hybridComponents(String family, String secondary) {
        Set<String> unique = new TreeSet<>();
        if (family != null && !family.isEmpty()) {
            unique.add(AsciiText.fold(family));
        }
        if (secondary != null) {
            for (String part : secondary.split(",")) {
                if (!part.isEmpty()) {
                    unique.add(part);
                }
            }
        }
        boolean anyPqc = unique.stream().anyMatch(AssetNormalizer::isPqcFamily);
        boolean anyClassical = unique.stream().anyMatch(token -> !isPqcFamily(token));
        return anyPqc && anyClassical ? List.copyOf(unique) : List.of();
    }

    /**
     * Whether a secondary token names a post-quantum family, with or without its parameter-set size.
     *
     * <p>
     * {@code PQC_FAMILIES} holds bare tokens while {@link #sizedFamilyToken} emits the sized spelling, so a plain
     * membership test saw {@code ml-kem} and missed {@code ml-kem-768} -- the standard parameter set. The classical
     * half then won the family, and a migrated hybrid read as un-migrated to any rule keyed on family plus hybrid
     * components.
     */
    private static boolean isPqcFamily(String token) {
        return PQC_FAMILIES.contains(token)
                || PQC_FAMILIES.contains(FAMILY_SIZE_SUFFIX.matcher(token).replaceFirst(""));
    }

    /**
     * Every other identity-bearing token the name carries beside its family.
     *
     * <p>
     * This is the fix for the highest-severity defect unseen data found: the digest was being dropped from composite
     * constructions, so {@code MD5withRSA} merged with {@code SHA256withRSA} and {@code HMAC-MD5} with
     * {@code HMAC-SHA1} -- silently erasing a weak-crypto finding, which is the one outcome an inventory must never
     * produce. {@code 3DES-CMAC} versus {@code AES-CMAC} is the same defect with a cipher instead of a digest, so the
     * rule is stated over families generally rather than over digests specifically.
     */
    public String secondaryTokens(String name, String winner) {
        if (name == null || AsciiText.isBlank(name)) {
            return "";
        }
        Set<String> found = new LinkedHashSet<>();
        Map<String, String> familyOf = new HashMap<>();
        boolean hybrid = winner != null && HYBRID_FAMILIES.contains(winner);
        // No text is stripped before the scan. Stripping the winner's matched text was tried and REVERTED: it removed
        // the spurious `dsa` read out of `ECDSA`, and it also removed the digest from `curve25519-sha256`, merging an
        // SSH key agreement with a bare X25519 and erasing the hash.
        String haystack = hybrid ? SEPARATORS.matcher(name).replaceAll("") : name;
        for (IdentityTables.GrammarRule rule : tables.nameGrammar()) {
            if (rule.family().equals(winner)) {
                continue;
            }
            Matcher matcher = (hybrid ? rule.unguarded() : rule.loose()).matcher(haystack);
            if (matcher.find()) {
                String token = sizedFamilyToken(rule.family(), matcher.group(), haystack.substring(matcher.end()));
                found.add(token);
                // The token alone cannot answer which family produced it, and the fold below has to know: the token
                // carries a size, so reading its family back out of the string is what truncated `sha-2` to `sha`.
                familyOf.putIfAbsent(token, rule.family());
            }
        }
        if (winner != null) {
            // A token that is merely a slice of the winning family's own token says nothing the family slot has not
            // already said. Comparing against the family TOKEN rather than against the matched text is what keeps
            // `poly1305` inside `ChaCha20-Poly1305` and `sha-2-256` inside `curve25519-sha256`, both of which name a
            // second construction rather than re-spelling the first.
            String foldedWinner = AsciiText.fold(winner);
            found.removeIf(token -> restatesWinner(foldedWinner, familyOf.get(token)));
        }
        // Markers scan the ORIGINAL name, not the winner-stripped haystack: a marker is often part of the winning
        // token and still identity-bearing. `ChaCha20-Poly1305` is matched whole by its own rule, so scanning a
        // stripped haystack lost the `poly1305` marker and merged an AEAD with the bare stream cipher.
        for (IdentityTables.SecondaryMarker marker : tables.secondaryMarkers()) {
            Matcher matcher = marker.pattern().matcher(name);
            if (matcher.find()) {
                // A capturing group makes the captured value part of the token, so a group or modp number
                // discriminates rather than being discarded.
                found
                        .add(marker.label()
                                + (matcher.groupCount() > 0 && matcher.group(1) != null ? matcher.group(1) : ""));
            }
        }
        return String.join(",", new TreeSet<>(found));
    }

    /**
     * Whether a secondary token's own family is already spelled inside the winning family's token.
     *
     * <p>
     * <b>The family, not the token's first hyphen-part.</b> A token carries its size -- {@link #sizedFamilyToken}
     * renders {@code SHA-2} at 256 bits as {@code sha-2-256} -- so the predecessor's
     * {@code foldedWinner.contains(token.split("-")[0])} truncated the family to {@code sha}, which {@code sha-3}
     * contains. {@code SHA-256 with SHA3} and {@code SHA3-256 with} therefore both produced
     * {@code ALG|SHA-3|256||||with}: the weak-crypto erasure this filter exists to prevent, performed by the filter.
     * Comparing the family the rule actually named keeps {@code sha-2} beside a SHA-3 winner and still folds away the
     * {@code dsa} that {@code ecdsa} spells, the {@code rsa} that {@code rsaes-oaep} spells and the {@code chacha20}
     * that {@code chacha20-poly1305} spells.
     *
     * <p>
     * <b>The containment stays a plain substring test, and that is ratified rather than sloppy.</b> Of the table's 130
     * families, 22 folded pairs contain one another, and four look accidental: {@code aes} inside {@code rsaes-oaep}
     * and {@code rsaes-pkcs1}, {@code ec} inside {@code classic mceliece}, {@code scrypt} inside {@code yescrypt}.
     * Tightening the rule to require alignment with a hyphen-part -- begins-with, or ends-with leaving a registry token
     * -- was implemented and reverted: it re-keyed vectors {@code gen-218} and {@code gen-219}, whose components are
     * named literally {@code RSAES-OAEP} and whose ratified pre-image {@code ALG|RSAES-OAEP||||OAEP|} carries an
     * <em>empty</em> variant slot. For that name there is no second construction to preserve, only a spelling artefact,
     * and the ratified answer is to erase it.
     *
     * <p>
     * What no artefact settles is a name stating both -- {@code RSAES-OAEP-AES256} -- where the same rule erases an AES
     * the producer really did state. Separating the two needs the match position, which is what the reverted attempt
     * used; no corpus row and no vector carries such a name, so it is an open adjudication on core#2165 rather than a
     * defect to patch under a ratified vector.
     */
    private boolean restatesWinner(String foldedWinner, String family) {
        String folded = AsciiText.fold(family);
        return folded != null && foldedWinner.contains(folded) && !folded.equals(foldedWinner);
    }

    /**
     * A secondary family token plus the size its own matched spelling carries.
     *
     * <p>
     * The token alone is not enough. {@code SHA-2} is one family token for four digest lengths, so
     * {@code SHA256withRSA}, {@code SHA384withRSA} and {@code SHA512withRSA} produced ONE identity -- five corpus keys
     * mixed digest lengths, all from real producer spellings. That is weak-crypto erasure one level down: split by
     * digest FAMILY, then merged by digest LENGTH.
     *
     * <p>
     * The run taken is the first digit run after the matched text's own leading letters, and failing that the run
     * immediately following the whole match -- both local, both order-free, so two implementations cannot disagree.
     * Locality is what keeps the rule honest: reading any digit run out of the match let {@code XChaCha20-Poly1305}
     * produce {@code chacha20-1305}, a token that means nothing.
     */
    String sizedFamilyToken(String family, String matched, String tail) {
        // A grammar rule always names a family, so the fold of it is never null. Asserted rather than assumed, because
        // both guards below read the token and a null one would fail them with an NPE instead of an answer.
        String token = Objects.requireNonNull(AsciiText.fold(family), "a grammar rule always names a family");
        String run = null;
        Matcher local = LOCAL_SIZE_RUN.matcher(matched);
        if (local.lookingAt()) {
            run = local.group(1);
        }
        if (run == null || token.contains(run)) {
            Matcher adjacent = ADJACENT_SIZE_RUN.matcher(tail);
            run = adjacent.lookingAt() ? adjacent.group(1) : null;
        }
        if (run == null || token.contains(run)) {
            return token;
        }
        return token + "-" + run;
    }

    /**
     * Family, provenance, the OID's own opinion, and whether it was refuted. Returns the entry still usable for
     * enrichment, if any.
     *
     * <p>
     * Three outcomes, not two. Agreement corroborates. <b>Subsumption</b> -- one side is a pseudo-family the other
     * belongs to -- lets the concrete token win <em>without</em> refuting the OID, which matters because
     * {@code 1.2.840.10045.3.1.7} yields family EC plus a curve: treating EC versus ECDSA as a contradiction would
     * discard the curve and break 1.6/1.7 parity, since 1.6 has no curve field at all. Only a genuine cross-group
     * contradiction refutes, and there the name wins.
     */
    private IdentityTables.OidEntry deriveFamily(NormalizedAsset norm, JsonNode algorithm) {
        IdentityTables.OidEntry entry = oidLookup(norm.oid());
        if (isCipherSuiteName(norm.name())) {
            norm.setFamily(null);
            norm.setFamilySource("cipher-suite name");
            norm.note("name denotes a cipher suite, not a single algorithm");
            return null;
        }

        String declared = boundedText(norm, algorithm, "algorithmFamily");
        String fromOid = entry == null ? null : entry.family();
        String fromName = familyFromName(norm.name());
        norm.setOidDerivedFamily(fromOid);

        boolean unvocabularied = false;
        if (declared != null && !AsciiText.isBlank(declared) && !tables.isSentinel(declared)) {
            String token = tables.familyToken(AsciiText.strip(declared));
            if (token == null) {
                // A producer-supplied "authoritative" identifier, and the only one that used to be taken verbatim:
                // 11 corpus assets declare values outside the vocabulary and 9 same-name groups split because of it.
                unvocabularied = true;
                norm
                        .note("R10: declared algorithmFamily " + declared
                                + " is not a legal registry token and does not "
                                + "enter the key; family derived from the name instead");
            } else if (fromName != null && tables.subsumes(token, fromName)) {
                // One producer declares the broad pseudo-family RSA in 1.7 for an asset named RSAES-OAEP, while the
                // same asset on 1.6 has no family and the name yields the concrete token. Preferring the concrete
                // member makes the two spec versions agree instead of splitting.
                return settle(norm, fromName, "name (declared subsumed)", fromOid, entry);
            } else {
                return settle(norm, token, "producer", fromOid, entry);
            }
        }

        return reconcileOidAndName(norm, fromOid, fromName, entry,
                unvocabularied ? " (declaration unvocabularied)" : "");
    }

    /**
     * Elects the family when the producer declared none the vocabulary accepts, leaving only the arc and the name.
     *
     * <p>
     * Agreement and subsumption both settle; a genuine disagreement is the only case that records a conflict, and it
     * keeps the name because a refuted arc is the weaker witness -- the arc is one token a producer may have copied,
     * while the name is the string the asset is actually called.
     *
     * <p>
     * Every null test here is its own: the callers pass whatever the arc and the grammar produced, including nothing
     * from either, and "neither witness spoke" is a real outcome rather than a guard against one.
     */
    private IdentityTables.OidEntry reconcileOidAndName(NormalizedAsset norm, String fromOid, String fromName,
            IdentityTables.OidEntry entry, String suffix) {
        if (fromOid != null && fromName != null) {
            return reconcileBothWitnesses(norm, fromOid, fromName, entry, suffix);
        }
        if (fromName != null) {
            return settleAgreed(norm, fromName, "name" + suffix, entry);
        }
        if (fromOid != null) {
            return settleAgreed(norm, fromOid, "oid" + suffix, entry);
        }
        norm.setFamily(null);
        norm.setFamilySource("none" + suffix);
        return null;
    }

    /**
     * Both the arc and the name named a family: agreement and either direction of subsumption settle, the rest is a
     * conflict.
     */
    private IdentityTables.OidEntry reconcileBothWitnesses(NormalizedAsset norm, String fromOid, String fromName,
            IdentityTables.OidEntry entry, String suffix) {
        if (fromOid.equals(fromName)) {
            return settleAgreed(norm, fromOid, "corroborated" + suffix, entry);
        }
        if (tables.subsumes(fromOid, fromName)) {
            return settleAgreed(norm, fromName, "name (oid subsumed)" + suffix, entry);
        }
        if (tables.subsumes(fromName, fromOid)) {
            return settleAgreed(norm, fromOid, "oid (name subsumed)" + suffix, entry);
        }
        norm.setFamily(fromName);
        norm.setFamilySource("name (oid refuted)" + suffix);
        norm.setOidConflict(true);
        return null;
    }

    /**
     * Applies a winning token and decides whether the arc contradicts it.
     *
     * <p>
     * The corroboration does not depend on where the winning token came from. A real 1.7 fixture declares ML-KEM on
     * {@code ML-KEM-1024} while carrying a fabricated {@code id-aes256-wrap-pad} arc, and the arc's AES-256 size then
     * overwrote the parameter set with 256 -- a factually wrong stored value for a 1024-bit KEM, and a guaranteed split
     * from the same asset's 1.6 rendering, which refutes the arc correctly.
     */
    private IdentityTables.OidEntry settle(NormalizedAsset norm, String winner, String source, String fromOid,
            IdentityTables.OidEntry entry) {
        boolean contradicts = fromOid != null && !fromOid.equals(winner) && !tables.subsumes(fromOid, winner)
                && !tables.subsumes(winner, fromOid);
        norm.setFamily(winner);
        norm.setFamilySource(source);
        norm.setOidConflict(contradicts);
        // A refuted OID forfeits every further contribution: if it is wrong about the family there is no reason to
        // trust its size, mode or curve.
        return contradicts ? null : entry;
    }

    private IdentityTables.OidEntry settleAgreed(NormalizedAsset norm, String winner, String source,
            IdentityTables.OidEntry entry) {
        norm.setFamily(winner);
        norm.setFamilySource(source);
        norm.setOidConflict(false);
        return entry;
    }

    private void deriveParameterSet(NormalizedAsset norm, JsonNode algorithm, IdentityTables.OidEntry enrichment) {
        List<String> notes = new ArrayList<>();
        norm.setParameterSet(parseParameterSet(norm.name(), algorithm.get(CbomNames.PARAMETER_SET_IDENTIFIER), notes));
        notes.forEach(norm::note);
        rejectDigestLengthAsKeySize(norm);
        if (norm.parameterSet() == null) {
            norm.setParameterSet(intrinsicParameterSet(norm.name()));
        }
        // A leaf arc is definitive and OVERRIDES the name parse: names are ambiguous (`SHA-512/224` offers two digit
        // runs and the name parse takes the first) while a leaf arc names exactly one algorithm.
        if (enrichment != null && enrichment.parameterSet() != null) {
            if (!enrichment.parameterSet().equals(norm.parameterSet())) {
                norm
                        .note("parameterSet " + norm.parameterSet() + " from name overridden by leaf arc "
                                + enrichment.matchedArc() + " -> " + enrichment.parameterSet());
            }
            norm.setParameterSet(enrichment.parameterSet());
        }
    }

    /**
     * Key or digest size, whitelisted, and never read out of a mode or a curve.
     *
     * <p>
     * {@code parameterSetIdentifier} is polysemous in real output -- measured across one producer it carries a key
     * size, a digest size, a cipher mode, a MAC name and a curve name -- so a numeric reading is tried first and the
     * name is parsed only as a fallback.
     */
    public Integer parseParameterSet(String name, JsonNode parameterSetIdentifier, List<String> notes) {
        Integer declared = parameterSetFromIdentifier(parameterSetIdentifier, notes);
        if (declared != null) {
            return declared;
        }
        return parameterSetFromName(name, notes);
    }

    /**
     * The size the producer declared, or {@code null} when it declared none this normalizer will take.
     *
     * <p>
     * A rejected declaration is not silence: a stoplisted token and a curve name each leave a note explaining what the
     * value actually was, because falling through to the name derivation with no record made a producer's wrong
     * declaration indistinguishable from an absent one.
     */
    private Integer parameterSetFromIdentifier(JsonNode parameterSetIdentifier, List<String> notes) {
        if (parameterSetIdentifier == null) {
            return null;
        }
        if (parameterSetIdentifier.isNumber() && !parameterSetIdentifier.isBoolean()) {
            // Refused before `decimalValue()`, which throws NumberFormatException on a non-finite double: Jackson
            // parses `1e400` into DoubleNode(Infinity), and the throw escaped as a RuntimeException that the extractor
            // catches as a whole-component skip. An unreadable side field costs its own slot, never the row -- the
            // same ruling `boundedText` applies to an over-long one. Keyed on the number, not the node shape: a
            // mapper with USE_BIG_DECIMAL_FOR_FLOATS hands the same literal over as a DecimalNode, which is neither a
            // double nor a float and whose exact value is a 401-digit integer that used to land verbatim in a note.
            if (parameterSetIdentifier.isFloatingPointNumber()
                    && !Double.isFinite(parameterSetIdentifier.doubleValue())) {
                notes.add(NON_FINITE_PARAMETER_SET_NOTE);
                return null;
            }
            // The exact value reaches `accept`, so a refusal names what the producer wrote. Through `(int)` a
            // saturating cast made `9007199254740993` refused as `size 2147483647 outside whitelist` -- a number
            // nobody sent. What this does NOT do is reject `64.0000000000000000001`: measured on this project's
            // mapper, that literal arrives as `DoubleNode(64.0)` because `USE_BIG_DECIMAL_FOR_FLOATS` is off, so its
            // precision is gone before this method sees it and `decimalValue()` returns 64.0 too. Rejecting it would
            // be a mapper-level change, and no value inside the 64..16384 whitelist keys differently either way --
            // doubles are exact on every integer below 2^53. Recorded because a review pass asked for the exact
            // check as a fix for that example, and it is not one.
            BigDecimal exact = parameterSetIdentifier.decimalValue().stripTrailingZeros();
            return exact.scale() <= 0
                    ? accept(exact.toBigIntegerExact(), CbomNames.PARAMETER_SET_IDENTIFIER, notes)
                    : null;
        }
        String spelled = boundedText(parameterSetIdentifier);
        if (spelled == null) {
            if (parameterSetIdentifier.isTextual()) {
                notes.add(droppedFieldNote(CbomNames.PARAMETER_SET_IDENTIFIER));
            }
            return null;
        }
        String text = AsciiText.strip(spelled);
        if (DIGITS.matcher(text).matches()) {
            return accept(new BigInteger(text), CbomNames.PARAMETER_SET_IDENTIFIER, notes);
        }
        if (tables
                .sizeStoplist()
                .stream()
                .anyMatch(token -> AsciiText.lookupKey(token).equals(AsciiText.lookupKey(text)))) {
            notes.add("parameterSetIdentifier " + text + " is a mode/MAC, not a size");
        } else if (canonicalCurve(text) != null) {
            notes.add("parameterSetIdentifier " + text + " is a curve, not a size");
        }
        return null;
    }

    /** The size read out of the component name, first from a whitelisted digit run and then from a trailing level. */
    private Integer parameterSetFromName(String name, List<String> notes) {
        if (name == null || AsciiText.isBlank(name)) {
            return null;
        }
        Matcher runs = DIGIT_RUN_2_TO_5.matcher(stripStoplist(ComponentNames.stripOpaqueTokens(name)));
        while (runs.find()) {
            Integer accepted = accept(Integer.parseInt(runs.group()), "name", notes);
            if (accepted != null) {
                return accepted;
            }
        }
        // Nothing passed the key-size whitelist. A trailing standalone integer is then a PARAMETER LEVEL, not a key
        // size, and it must bypass the floor: `ML-DSA-44` keyed identically to bare `ML-DSA` because 44 is below 64,
        // while `-65` and `-87` separated only by the accident of clearing it. Applied to the STRIPPED name, so a
        // trailing digit run belonging to a curve cannot be read as a level -- and with the family rule's own match
        // removed, so a digit the family spelling consumed is not read a second time as a level: `SHA-1` stored a
        // parameter set of 1 and split from `SHA1`, `MD-5` from `MD5`. A digit run consumed by one slot must never
        // be consumed again by another, and the family is a slot.
        Matcher level = PARAMETER_LEVEL.matcher(AsciiText.strip(stripStoplist(withoutFamilyToken(name))));
        if (!level.find()) {
            return null;
        }
        notes
                .add("parameter level " + level.group(1) + " accepted below the key-size floor: it labels a "
                        + "parameter set, not a key length");
        return Integer.parseInt(level.group(1));
    }

    /** The name with the text the first matching grammar rule consumed replaced by a space. */
    private String withoutFamilyToken(String name) {
        for (IdentityTables.GrammarRule rule : tables.nameGrammar()) {
            Matcher matcher = rule.strict().matcher(name);
            if (matcher.find()) {
                return matcher.replaceFirst(" ");
            }
        }
        return name;
    }

    /**
     * The whitelist decides before the value is narrowed. {@code DIGITS} is unbounded, so a schema-valid digit-only
     * {@code parameterSetIdentifier} of twenty digits reached {@code Integer.parseInt} and threw -- and the throw cost
     * the whole asset its row, where an out-of-range size is supposed to cost only the size slot plus a note.
     */
    private Integer accept(BigInteger candidate, String origin, List<String> notes) {
        if (candidate.compareTo(BigInteger.valueOf(tables.sizeMin())) >= 0
                && candidate.compareTo(BigInteger.valueOf(tables.sizeMax())) <= 0) {
            return candidate.intValueExact();
        }
        notes.add("size " + candidate + " from " + origin + " outside whitelist");
        return null;
    }

    private Integer accept(int candidate, String origin, List<String> notes) {
        if (candidate >= tables.sizeMin() && candidate <= tables.sizeMax()) {
            return candidate;
        }
        notes.add("size " + candidate + " from " + origin + " outside whitelist");
        return null;
    }

    /**
     * Names that fully determine their own parameter set. A bare {@code Ed25519} and an {@code Ed25519} whose producer
     * also emitted {@code parameterSetIdentifier: 256} are one algorithm, and splitting them is an under-merge on a
     * very common asset. Ed448 keys are 456 bits, not 448 -- the name is the curve, not the size.
     */
    public Integer intrinsicParameterSet(String name) {
        if (name == null || AsciiText.isBlank(name)) {
            return null;
        }
        for (Map.Entry<String, Integer> intrinsic : tables.nameIntrinsicSizes().entrySet()) {
            Pattern token = Pattern
                    .compile(LEFT_WORD_GUARD + Pattern.quote(intrinsic.getKey()) + RIGHT_WORD_GUARD,
                            Pattern.CASE_INSENSITIVE);
            if (token.matcher(name).find()) {
                return intrinsic.getValue();
            }
        }
        return null;
    }

    /** Drops a parameter set that is really the digest length of a signature scheme. */
    private void rejectDigestLengthAsKeySize(NormalizedAsset norm) {
        String family = norm.family() == null ? "" : norm.family();
        if (norm.parameterSet() == null || KEY_SIZE_FAMILIES.stream().noneMatch(family::startsWith)) {
            return;
        }
        // Only the NAME parse is suspect: a producer stating the size in the field is telling us the key size
        // directly, and the parse already prefers it.
        Matcher digest = DIGEST_IN_NAME.matcher(norm.name() == null ? "" : norm.name());
        while (digest.find()) {
            if (Integer.parseInt(digest.group(1)) == norm.parameterSet()) {
                norm
                        .note("parameterSet " + norm.parameterSet() + " discarded: it is the DIGEST length in "
                                + norm.name() + ", and for " + family + " the slot means the key size");
                norm.setParameterSet(null);
                return;
            }
        }
    }

    /**
     * First channel that yields a registry curve wins; provenance is recorded.
     *
     * <p>
     * 1.7 renamed {@code curve} to {@code ellipticCurve} but real 1.7 output uses both fields in one document: absence
     * from {@code ellipticCurve} while present in {@code curve} is the producer's own signal that the value is inferred
     * rather than observed.
     */
    private void deriveCurve(NormalizedAsset norm, JsonNode algorithm, IdentityTables.OidEntry enrichment) {
        String parameterSetIdentifier = boundedText(norm, algorithm, CbomNames.PARAMETER_SET_IDENTIFIER);
        List<String[]> channels = new ArrayList<>();
        channels.add(new String[]{boundedText(norm, algorithm, CbomNames.ELLIPTIC_CURVE), CbomNames.ELLIPTIC_CURVE});
        channels.add(new String[]{boundedText(norm, algorithm, "curve"), "curve (inferred by producer)"});
        channels.add(new String[]{parameterSetIdentifier, CbomNames.PARAMETER_SET_IDENTIFIER});
        channels.add(new String[]{enrichment == null ? null : enrichment.curve(), "oid"});
        // Only an EC-bearing family may take a curve from free text, or any incidental word that happens to be a
        // registry curve spelling attaches one: an asset named `AES-256 key for Vesta` acquired `other/Vesta`.
        channels.add(new String[]{isCurveBearing(norm.family()) ? curveFromName(norm.name()) : null, "name"});

        for (String[] channel : channels) {
            String candidate = canonicalCurves(channel[0]);
            if (candidate != null) {
                norm.setCurve(candidate);
                norm.setCurveSource(channel[1]);
                return;
            }
        }
        for (String raw : List
                .of(nullToEmpty(boundedText(norm, algorithm, CbomNames.ELLIPTIC_CURVE)),
                        nullToEmpty(boundedText(norm, algorithm, "curve")))) {
            if (!AsciiText.isBlank(raw) && !tables.isSentinel(raw)) {
                norm.note("curve " + raw + " is not a registry token");
            }
        }
    }

    /**
     * Folds any producer spelling onto its equivalence class representative.
     *
     * <p>
     * The registry names one physical curve up to three times -- {@code nist/P-256}, {@code secg/secp256r1} and
     * {@code x962/prime256v1} all carry one OID -- so canonicalizing to "the registry spelling" is not enough: two
     * producers using two legal spellings would key differently.
     */
    public String canonicalCurve(String raw) {
        if (raw == null || AsciiText.isBlank(raw) || tables.isSentinel(raw)) {
            return null;
        }
        String text = AsciiText.strip(raw);
        String direct = tables.curveCanonical().get(text);
        return direct != null ? direct : tables.curveAliases().get(AsciiText.lookupKey(text));
    }

    /**
     * A curve slot from a producer field that may name more than one curve.
     *
     * <p>
     * A single spelling is resolved exactly as before. Only when the whole string is not a registry token is it split
     * on the separators producers actually use for "either of these" -- {@code X25519/X448}, {@code P-256, P-384} -- so
     * a legitimate spelling containing one of those characters can never be broken apart.
     */
    public String canonicalCurves(String raw) {
        String single = canonicalCurve(raw);
        if (single != null || raw == null || AsciiText.isBlank(raw)) {
            return single;
        }
        String[] parts = CURVE_ALTERNATIVES.split(AsciiText.strip(raw));
        if (parts.length < 2) {
            return null;
        }
        List<String> resolved = new ArrayList<>();
        for (String part : parts) {
            resolved.add(canonicalCurve(part));
        }
        return joinCurves(resolved);
    }

    /**
     * Every recognized curve spelling appearing as a word in the name, sorted.
     *
     * <p>
     * A name that names TWO curves keys on both. Returning only the longest spelling made {@code X25519/X448} share an
     * identity with plain {@code X25519} -- the X448 half disappeared from the inventory.
     */
    public String curveFromName(String name) {
        if (name == null || AsciiText.isBlank(name)) {
            return null;
        }
        List<String> found = new ArrayList<>();
        // Patterns come precompiled from the tables. Compiled here, this was 254 Pattern.compile calls per EC-bearing
        // name, which made normalization quadratic in the name length on producer-controlled text.
        for (IdentityTables.CurveSpelling spelling : tables.curveSpellingPatterns()) {
            if (spelling.word().matcher(name).find()) {
                found.add(canonicalCurve(spelling.spelling()));
            }
        }
        return joinCurves(found);
    }

    /** One curve token, or several joined with {@code +} in sorted order. */
    private static String joinCurves(List<String> curves) {
        Set<String> distinct = new TreeSet<>();
        curves.stream().filter(curve -> curve != null && !curve.isEmpty()).forEach(distinct::add);
        return distinct.isEmpty() ? null : String.join("+", distinct);
    }

    /** Only an EC-ish family may take a curve from free text in its name. */
    private boolean isCurveBearing(String family) {
        return family != null
                && ("EC".equals(family) || tables.pseudoFamilies().getOrDefault("EC", Set.of()).contains(family));
    }

    /**
     * Removes mode/MAC tokens and any recognized curve name from a name string.
     *
     * <p>
     * A digit run consumed by one slot must not be consumed again by another. Without the curve half,
     * {@code ECDSA-P-256} reads size 256 from its own <em>curve</em> name and collides with {@code ECDSA-SHA256}.
     */
    String stripStoplist(String name) {
        return tables.curveStrip().matcher(tables.stoplistStrip().matcher(name).replaceAll(" ")).replaceAll(" ");
    }

    private void deriveMode(NormalizedAsset norm, JsonNode algorithm, IdentityTables.OidEntry enrichment) {
        norm
                .setMode(normalizeMode(boundedText(norm, algorithm, "mode"),
                        boundedText(norm, algorithm, CbomNames.PARAMETER_SET_IDENTIFIER), norm.name()));
        if (norm.mode() == null && enrichment != null && enrichment.mode() != null) {
            // Through the same vocabulary the field and the name go through. Taken verbatim, an arc whose strand row
            // said `POLY1305` put a value outside `modeTokens` into the slot, and a ChaCha20-Poly1305 asset keyed
            // one way with the CMS arc and another without it. The generator refuses such a row now; this is the
            // loader-side half of the same rule, for an artifact that did not come out of the generator.
            String token = modeToken(enrichment.mode());
            if (token == null) {
                norm
                        .note("mode " + enrichment.mode() + " from arc " + enrichment.matchedArc()
                                + " is not a mode token and does not enter the key");
            }
            norm.setMode(token);
        }
    }

    /**
     * Mode from the spec field, else {@code parameterSetIdentifier}, else the name.
     *
     * <p>
     * Measured: the producer's {@code mode} field is populated on four assets and its value is the literal string
     * {@code unknown} every time -- zero real values -- while the real mode sits in {@code parameterSetIdentifier} as
     * {@code GCM}. A stored {@code unknown} would split the asset from every producer that simply omits the field, so
     * sentinels are treated as absent.
     */
    public String normalizeMode(String mode, String parameterSetIdentifier, String name) {
        for (String candidate : new String[]{mode, parameterSetIdentifier}) {
            if (candidate != null && !tables.isSentinel(candidate)) {
                String token = modeToken(candidate);
                if (token != null) {
                    return token;
                }
            }
        }
        if (name != null) {
            for (String token : tables.modeTokens()) {
                Pattern word = Pattern
                        .compile(LEFT_WORD_GUARD + Pattern.quote(token) + RIGHT_WORD_GUARD, Pattern.CASE_INSENSITIVE);
                if (word.matcher(name).find()) {
                    return AsciiText.upper(token);
                }
            }
        }
        return null;
    }

    /** The vocabulary's spelling of a mode a producer or an arc named, or {@code null} when it names none. */
    private String modeToken(String candidate) {
        for (String token : tables.modeTokens()) {
            if (AsciiText.lookupKey(token).equals(AsciiText.lookupKey(candidate))) {
                return AsciiText.upper(token);
            }
        }
        return null;
    }

    /**
     * Padding, field first then the name -- exactly parallel to mode.
     *
     * <p>
     * It has to be a real slot. Stripping padding tokens from the variant residue while representing them nowhere
     * merged {@code AES-128-CBC-PKCS7} with {@code AES-128-CBC-RAW}, which are different constructions.
     */
    private void derivePadding(NormalizedAsset norm, JsonNode algorithm) {
        String declared = boundedText(norm, algorithm, "padding");
        if (declared != null && !AsciiText.isBlank(declared) && !tables.isSentinel(declared)) {
            // Flattened exactly as the name is below: `PKCS#7` and `PKCS5Padding` are the same spellings in the field
            // as in a name, and compared raw the field refused both as out-of-vocabulary.
            String token = paddingSpelling(declared);
            // L7: the slot was an unbounded passthrough and has stored arbitrary producer text verbatim. Only a value
            // in the closed padding vocabulary may enter the key.
            if (tables.paddingTokens().stream().noneMatch(known -> AsciiText.upperPresent(known).equals(token))) {
                norm.note("L7: padding " + declared + " is outside the closed vocabulary and does not enter the key");
                return;
            }
            norm.setPadding(canonicalPadding(token));
            return;
        }
        if (norm.name() != null) {
            // Punctuation inside the token is dropped first: `PKCS#7` and `PKCS #7` are both common spellings, and
            // without this they fail to match a producer that puts the value in the field instead.
            String flattened = NON_ALPHANUMERIC.matcher(norm.name()).replaceAll("");
            for (String token : tables.paddingTokens()) {
                Pattern word = Pattern
                        .compile(Pattern.quote(token) + JCA_PADDING_SUFFIX + RIGHT_WORD_GUARD,
                                Pattern.CASE_INSENSITIVE);
                Matcher matcher = word.matcher(flattened);
                if (matcher.find()) {
                    norm.setPadding(canonicalPadding(token));
                    // The matched spelling, suffix included, so the residue pass strips what this slot consumed:
                    // recording the bare token left `padding` in the variant of `AES/CBC/PKCS5Padding` and split it
                    // from `AES/CBC/PKCS5` a second time, one slot over.
                    norm.setPaddingFromName(matcher.group());
                    return;
                }
            }
        }
    }

    /**
     * A declared padding reduced to the vocabulary's spelling: punctuation dropped, upper-cased, and the JCA
     * {@code Padding} suffix removed, so {@code padding: "PKCS5Padding"} copied out of a transformation string says
     * what {@code PKCS5} says.
     */
    private static String paddingSpelling(String declared) {
        String flattened = AsciiText.upperPresent(NON_ALPHANUMERIC.matcher(declared).replaceAll(""));
        return flattened.length() > JCA_PADDING_WORD.length() && flattened.endsWith(JCA_PADDING_WORD)
                ? flattened.substring(0, flattened.length() - JCA_PADDING_WORD.length())
                : flattened;
    }

    private String canonicalPadding(String token) {
        String upper = AsciiText.upper(token);
        return tables.paddingAliases().containsKey(upper) ? tables.paddingAliases().get(upper) : upper;
    }

    /**
     * Declared value, else {@code cryptoFunctions}, else the family default.
     *
     * <p>
     * The OID deliberately never supplies it: letting a correct arc contribute {@code block-cipher} where an OID-less
     * producer had nothing meant that adding a correct OID changed the identity key. The default table is total for the
     * same class of reason -- the field is present on only 88% of real assets, so a default that does not always fire
     * splits an omitting producer from a declaring one.
     */
    private void derivePrimitive(NormalizedAsset norm, JsonNode algorithm) {
        String declared = boundedText(norm, algorithm, "primitive");
        if (declared != null && !AsciiText.isBlank(declared) && !tables.isSentinel(declared)) {
            String stripped = AsciiText.strip(declared);
            // Every other typed slot is registry-bounded; this one is producer text straight through, and it lands in
            // an indexed column with no length CHECK. Past roughly 2704 bytes the btree itself refuses the row with
            // SQLSTATE 54000 -- not a constraint violation, so nothing names the field, and PostgreSQL reports it with
            // a DETAIL line carrying every column of the row. Costing the slot keeps that channel shut; the asset
            // still keys and still stores.
            if (stripped.codePointCount(0, stripped.length()) > MAX_PRIMITIVE_LENGTH) {
                norm
                        .note("the declared primitive exceeds " + MAX_PRIMITIVE_LENGTH
                                + " characters and was dropped rather than stored");
            } else if (!tables.isExpressiblePrimitive(stripped)) {
                // Same ruling as R10 on a declared algorithmFamily: a producer-supplied value outside the closed
                // vocabulary does not enter the key. `key-wrap` is 1.7-only, so taking it verbatim keys the 1.7
                // rendering of an asset apart from the 1.6 rendering that cannot express it -- the two-spec split
                // every other typed slot is bounded to prevent. Derivation below still answers.
                norm
                        .note("R10: declared primitive " + stripped + " is not expressible in CycloneDX 1.6 and does "
                                + "not enter the key; primitive derived instead");
            } else {
                norm.setPrimitive(stripped);
                return;
            }
        }
        String fromFunctions = primitiveFromFunctions(norm, algorithm.get("cryptoFunctions"));
        if (fromFunctions != null) {
            norm.setPrimitive(fromFunctions);
            return;
        }
        norm.setPrimitive(norm.family() == null ? null : tables.primitiveDefaults().get(norm.family()));
    }

    private String primitiveFromFunctions(NormalizedAsset norm, JsonNode functions) {
        if (functions == null || !functions.isArray()) {
            return null;
        }
        Set<String> tokens = new LinkedHashSet<>();
        functions.forEach(function -> {
            String spelled = boundedText(function);
            noteIfDropped(norm, function, "cryptoFunctions");
            if (!AsciiText.isBlank(spelled)) {
                tokens.add(AsciiText.strip(spelled).toLowerCase(Locale.ROOT));
            }
        });
        if (tokens.stream().anyMatch(CONFLICTING_FUNCTIONS::contains)) {
            return null;
        }
        tokens.removeAll(NEUTRAL_FUNCTIONS);
        Set<String> derived = new LinkedHashSet<>();
        tokens.stream().map(FUNCTION_PRIMITIVE::get).filter(java.util.Objects::nonNull).forEach(derived::add);
        return derived.size() == 1 ? derived.iterator().next() : null;
    }

    /**
     * An AE mode makes a cipher primitive {@code ae}, whichever the producer declared.
     *
     * <p>
     * Producers disagree about the same construction: for AES-128-GCM one emits {@code block-cipher} and another
     * {@code ae}, and both are defensible readings. Folding resolves it in one direction, restricted to cipher
     * primitives so a digest or a signature scheme can never be relabelled by a stray token.
     */
    private void foldAuthenticatedEncryption(NormalizedAsset norm) {
        // The null check on the primitive is not defensive noise: Set.of refuses a null argument outright, where the
        // reference's membership test simply answers false. An algorithm with no family and no declared primitive
        // reaches here with none.
        if (norm.mode() != null && norm.primitive() != null && AE_MODES.contains(AsciiText.upper(norm.mode()))
                && AE_FOLDABLE.contains(norm.primitive())) {
            norm.setPrimitive("ae");
        }
    }

    /**
     * What the name still says after every tuple slot has taken its share.
     *
     * <p>
     * The six other slots are not injective. Measured collisions between genuinely different algorithms:
     * {@code SLH-DSA-SHA2-128s} versus {@code -128f}, {@code AES-256-WRAP} versus {@code -WRAP-PAD}, {@code SHA-512}
     * versus {@code SHA-512/256}.
     *
     * <p>
     * This strips only what another slot actually consumed. An earlier version stripped the whole size stoplist, which
     * silently erased XTS, SIV, OCB and EAX: {@code AES-256}, {@code AES-256-XTS}, {@code AES-256-SIV},
     * {@code AES-256-OCB} and {@code AES-256-EAX} all collapsed onto one identity. Those are real, different ciphers
     * and the CycloneDX mode enum has no value for them, so the residue is the only place they can live.
     */
    public String variantResidue(String name, Integer parameterSet, String mode, String family, String paddingFromName,
            List<String> dropped) {
        if (name == null || AsciiText.isBlank(name)) {
            return null;
        }
        String stripped = strippedOfConsumedTokens(name, mode, paddingFromName);
        Set<String> kept = sizeRunsWorthKeeping(stripped, name, family, parameterSet);
        String letters = residualLetters(stripped, paddingFromName, dropped);
        String residue = withSynonymFolded(letters) + (kept.isEmpty() ? "" : "|" + String.join(",", kept));
        return residue.isEmpty() ? null : residue;
    }

    /** The name with every grammar rule, the mode and padding tokens this name yielded, and any curve removed. */
    private String strippedOfConsumedTokens(String name, String mode, String paddingFromName) {
        String stripped = name;
        for (IdentityTables.GrammarRule rule : tables.nameGrammar()) {
            stripped = rule.strict().matcher(stripped).replaceAll(" ");
        }
        for (String token : new String[]{mode, paddingFromName}) {
            if (token != null) {
                stripped = Pattern
                        .compile(Pattern.quote(token) + RIGHT_WORD_GUARD, Pattern.CASE_INSENSITIVE)
                        .matcher(stripped)
                        .replaceAll(" ");
            }
        }
        return tables.curveStrip().matcher(stripped).replaceAll(" ");
    }

    /** Every digit run the size slot did not already account for, plus the truncation and level markers. */
    private Set<String> sizeRunsWorthKeeping(String stripped, String name, String family, Integer parameterSet) {
        // Compared as BigInteger, kept as text. A component name is an unrestricted string, so a legitimate name
        // carrying a long decimal identifier threw here and cost the asset its row; the run itself still enters the
        // residue verbatim, leading zeros and all.
        BigInteger floor = BigInteger.valueOf(tables.sizeMin());
        Set<String> kept = new TreeSet<>();
        Matcher runs = DIGITS.matcher(stripped);
        while (runs.find()) {
            BigInteger value = new BigInteger(runs.group());
            if (value.compareTo(floor) >= 0
                    && (parameterSet == null || !value.equals(BigInteger.valueOf(parameterSet)))) {
                kept.add(runs.group());
            }
        }
        addTruncationMarker(kept, name, family, floor);
        addLevelMarkers(kept, stripped, parameterSet);
        return kept;
    }

    /**
     * A trailing separator-delimited digest length is a TRUNCATION marker, but only when the name carries a base length
     * too -- otherwise {@code SHA-256} would read its own only digit run as a truncation of itself. Both spellings must
     * produce the same marker: NIST writes {@code SHA-512/224} and producers write {@code SHA-512-224}.
     */
    private void addTruncationMarker(Set<String> kept, String name, String family, BigInteger floor) {
        int runsAtOrAboveFloor = 0;
        Matcher nameRuns = DIGITS.matcher(name);
        while (nameRuns.find()) {
            if (new BigInteger(nameRuns.group()).compareTo(floor) >= 0) {
                runsAtOrAboveFloor++;
            }
        }
        Matcher truncation = TRUNCATION.matcher(AsciiText.strip(name));
        if (truncation.find() && family != null && tables.truncatableFamilies().contains(family)
                && runsAtOrAboveFloor >= 2 && Integer.parseInt(truncation.group(1)) >= tables.sizeMin()) {
            kept.add("t" + truncation.group(1));
        }
    }

    /**
     * A digit attached to a letter is a LEVEL marker, not a size, and it survives the size floor: {@code BIKE-L1},
     * {@code -L3} and {@code -L5} are three different parameter sets and all three merged because 1, 3 and 5 fall below
     * the minimum. A level marker must not be a slice of the parameter set: {@code RSA-4096} and {@code RSA4096}
     * produced residues {@code |096} versus nothing and split 23 corpus rows.
     */
    private void addLevelMarkers(Set<String> kept, String stripped, Integer parameterSet) {
        Matcher levels = LEVEL_MARKER.matcher(stripped);
        while (levels.find()) {
            String digits = NON_DIGITS.matcher(levels.group(1)).replaceAll("");
            if (parameterSet == null || !String.valueOf(parameterSet).endsWith(digits)) {
                kept.add(AsciiText.fold(levels.group(1)));
            }
        }
    }

    /**
     * The flattened letters left in the name, with the padding token removed only when this name is where it was read.
     *
     * <p>
     * L7, half-fixed and deliberately so. Filtering this residue against a closed construction vocabulary was tried and
     * REVERTED: it removed 72 spurious rows but introduced over-merges in the severe direction, because free text in a
     * name is sometimes noise and sometimes a construction. {@code KEM Combiner (SHA-256)} merged with plain
     * {@code SHA-256}, which is wrong: a KEM combiner using SHA-256 is not SHA-256. Over-splitting is visible and
     * repairable; over-merging is silent corruption.
     */
    private String residualLetters(String stripped, String paddingFromName, List<String> dropped) {
        String letters = AsciiText.foldPresent(NON_LETTERS.matcher(stripped).replaceAll(""));
        if (!letters.isEmpty() && !tables.variantVocabulary().contains(letters)) {
            dropped.add(letters);
        }
        // Stripping every padding spelling unconditionally ate a meaningful token: `AES-128-CBC-OpenPKCS11` collapsed
        // onto `AES-128-CBC-Open` because `pkcs` is a substring of `openpkcs`.
        if (paddingFromName == null) {
            return letters;
        }
        String flattened = NON_LETTERS.matcher(paddingFromName).replaceAll("").toLowerCase(Locale.ROOT);
        if (!flattened.isEmpty() && letters.endsWith(flattened)) {
            return letters.substring(0, letters.length() - flattened.length());
        }
        if (!flattened.isEmpty() && letters.startsWith(flattened)) {
            return letters.substring(flattened.length());
        }
        return letters;
    }

    /**
     * Synonyms fold at a PREFIX or SUFFIX only, longest key first.
     *
     * <p>
     * Free substring replacement corrupted unrelated words -- {@code kw} inside "backward" turned
     * {@code SHAKE256-BackwardSecure} into {@code bacwrapardsecure} -- while whole-residue matching missed compound
     * residues such as {@code kwrfc}. The first spelling that matches wins and the rest are not considered.
     */
    private String withSynonymFolded(String letters) {
        List<String> spellings = new ArrayList<>(tables.variantSynonyms().keySet());
        spellings.sort((left, right) -> Integer.compare(right.length(), left.length()));
        for (String spelling : spellings) {
            String replacement = tables.variantSynonyms().get(spelling);
            if (letters.equals(spelling)) {
                return replacement;
            }
            if (letters.startsWith(spelling)) {
                return replacement + letters.substring(spelling.length());
            }
            if (letters.endsWith(spelling)) {
                return letters.substring(0, letters.length() - spelling.length()) + replacement;
            }
        }
        return letters;
    }

    private static final Pattern NON_DIGITS = Pattern.compile("\\D");

    private static JsonNode objectOrEmpty(JsonNode node) {
        return node != null && node.isObject()
                ? node
                : com.fasterxml.jackson.databind.node.JsonNodeFactory.instance.objectNode();
    }

    /**
     * A producer field's text, or {@code null} when the node is not textual or the value exceeds
     * {@code MAX_NORMALIZABLE_LENGTH}.
     *
     * <p>
     * The gate in front of every producer string <em>this normalizer</em> reads before a grammar, a table or an arc
     * walk sees it: the algorithm-property fields and the {@code oid}. The name carried the bound and nothing else did,
     * so a producer's {@code ellipticCurve}, {@code parameterSetIdentifier} or {@code oid} reached the alternatives
     * split, a {@code BigInteger} parse and the per-arc OID walk at whatever length the JSON reader allowed -- 20
     * million characters by default, with no body cap on the upload -- and the last two are quadratic. Measured at this
     * bound's absence, a 200 000-arc OID took 265 seconds through {@code oidLookup}. No registry spelling, mode,
     * padding or arc comes near the bound, so nothing real reads as absent.
     *
     * <p>
     * It is not the gate for the strings the identity tiers read themselves -- a material id or fingerprint content, a
     * certificate serial, a protocol type -- which reach a pre-image at the parser's length. Those paths are linear,
     * roughly 10 ns per character at four million, so the bound is not needed for availability there and is not
     * applied; what it would decide is which of them enters a key, which is a ratification question. The asset type is
     * deliberately unbounded too -- see {@link #normalize}.
     *
     * <p>
     * Absent rather than refused: an over-long side field costs its own slot, not the row -- the ruling the over-long
     * primitive already follows. The name alone is refused, by {@link #requireNormalizableName}, because there the
     * bound is the storage bound and a refused name could never have been written; none of these fields is stored raw.
     */
    private static String boundedText(JsonNode node) {
        String value = node != null && node.isTextual() ? node.textValue() : null;
        return exceedsNormalizableLength(value) ? null : value;
    }

    /**
     * {@link #boundedText} for a named field of {@code parent}, recording the drop on the row when the bound fires.
     *
     * <p>
     * Reading as absent is the ruled behaviour, but absent is the MERGE direction: two {@code RSA} rows whose over-long
     * {@code parameterSetIdentifier}s differ both key {@code ALG|RSA|||||}, where the readable spellings kept them
     * apart. The over-long primitive already leaves a note; without one here the merge left no trace at all. Several
     * fields are read more than once along the derivation, so the note is recorded once per field.
     */
    private static String boundedText(NormalizedAsset norm, JsonNode parent, String field) {
        JsonNode node = parent.get(field);
        noteIfDropped(norm, node, field);
        return boundedText(node);
    }

    private static void noteIfDropped(NormalizedAsset norm, JsonNode node, String field) {
        if (node != null && node.isTextual() && exceedsNormalizableLength(node.textValue())) {
            String note = droppedFieldNote(field);
            if (!norm.notes().contains(note)) {
                norm.note(note);
            }
        }
    }

    private static String droppedFieldNote(String field) {
        return "the declared " + field + " exceeds " + MAX_NORMALIZABLE_LENGTH
                + " characters and was dropped rather than normalized";
    }

    /**
     * Its own note, not {@link #droppedFieldNote}'s: that one says the value exceeded 1024 characters, which for a
     * five-character {@code 1e400} is false in a provenance block that is stored and can be served.
     */
    static final String NON_FINITE_PARAMETER_SET_NOTE = "the declared " + CbomNames.PARAMETER_SET_IDENTIFIER
            + " is not a finite number and was dropped rather than normalized";

    private static String nullToEmpty(String value) {
        return value == null ? "" : value;
    }

    private static String joinNonEmpty(String separator, String... parts) {
        List<String> present = new ArrayList<>();
        for (String part : parts) {
            if (part != null && !part.isEmpty()) {
                present.add(part);
            }
        }
        return present.isEmpty() ? null : String.join(separator, present);
    }
}
