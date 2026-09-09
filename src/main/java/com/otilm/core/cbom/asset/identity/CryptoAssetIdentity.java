package com.otilm.core.cbom.asset.identity;

import com.fasterxml.jackson.databind.JsonNode;
import com.otilm.core.model.cbom.CryptoAssetIdentityGuard;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeSet;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * The ratified identity chain: routes a component to its tier, builds that tier's pre-image, and hashes it.
 *
 * <p>
 * <b>Routing is on {@code cryptoProperties.assetType} alone</b>, never on which properties block happens to be present.
 * A producer bug once stamped {@code relatedCryptoMaterialProperties} onto algorithms and certificates; a
 * presence-based router would have pulled those into the wrong chain and minted phantom material rows from the empty
 * blocks it left behind.
 *
 * <p>
 * The identity value is SHA-256 over the pre-image encoded UTF-8, rendered lowercase hex. Slots join with {@code |} and
 * are percent-escaped; field order within a tier is fixed. <b>The outer escape set applies to outer slots only</b> -- a
 * value that goes into a string which is then hashed, with only the digest reaching a slot, keeps its spaces and is
 * escaped against that inner string's own delimiter alone, as {@link #dnPreImage} does.
 *
 * <p>
 * This exists as bytes rather than as groupings because a partition-based suite cannot check a hash. One
 * proof-of-concept round passed 62 of 62 scenarios while carrying 66 unresolved guesses: two conformant implementations
 * could write different keys for one asset and never be able to share a table.
 */
public record CryptoAssetIdentity(AssetNormalizer normalizer) {

    /** The tier vocabulary's version marker, carried inside certificate pre-images. */
    private static final String SPEC_ID = "v1";

    private static final Pattern CLAIM_PROPERTY = Pattern
            .compile("lifecycle|observation|assurance|deployment", Pattern.CASE_INSENSITIVE);

    /** The token a claimed asset carries into its key, and the value the claim detector reports. */
    private static final String CLAIMED = "claimed";

    private static final Set<String> CLAIM_VALUES = Set
            .of(CLAIMED, "declared", "capability", "supported", "supports", "capable");

    /**
     * Posture spellings a protocol name may carry, each mapped to the token that enters the key. Deliberately closed: a
     * free-text discriminator over-splits. The value is what is emitted, not the spelling that matched: emitting the
     * spelling keyed {@code TLS Suite-B} and {@code TLS SuiteB} apart, one posture as two.
     */
    private static final String SUITE_B = "suite-b";

    private static final Map<String, String> POSTURE_TOKENS = Map
            .of("cnsa", "cnsa", "pqc", "pqc", "fips", "fips", SUITE_B, SUITE_B, "suiteb", SUITE_B);

    /**
     * A port is digits after a colon. The class used to admit a slash as well, so {@code TLS/12} contributed port 12
     * and a date in a name contributed its day and month.
     */
    private static final Pattern ENDPOINT_PORT = Pattern.compile(":(\\d{2,5})(?![0-9A-Za-z])");

    private static final Pattern PROTOCOL_PREFIX = Pattern
            .compile("^(?:DTLS|TLS|SSL|SSH)\\s*v?", Pattern.CASE_INSENSITIVE);

    /** The related-asset type that names a certificate's public key, once separators and case are dropped. */
    private static final String PUBLIC_KEY_REFERENCE = "publickey";

    private static final Pattern TWO_DIGITS = Pattern.compile("\\d{2}");

    private static final Pattern ALL_DIGITS = Pattern.compile("\\d+");

    /** The pipeline this chain keys over. Exposed so a caller builds document scope from the same tables. */
    @Override
    public AssetNormalizer normalizer() {
        return normalizer;
    }

    /**
     * The identity of one component, the chain step that produced it, and everything the pipeline derived.
     *
     * <p>
     * {@code guard} is the safety rule that forced this asset to stay its own row, or {@code null} when none fired. It
     * is derived here rather than by a caller because two of the three signals -- a refuted certificate digest, and a
     * bare-CN subject -- are visible only inside the certificate tier.
     *
     * <p>
     * {@code findings} is what the pipeline has to tell the producer: the redaction findings, and one line for every
     * occurrence whose stated location rendered as no location -- see {@link Occurrences#triples(JsonNode, List)}. They
     * are gathered here rather than by the caller because the occurrence pass runs here, once, for the tiers that key
     * on it, and a caller re-running it to learn what was refused would sanitize every location a second time.
     *
     * <p>
     * <b>The generated {@code toString} is overridden deliberately.</b> A record prints every component, so the default
     * would put the identity key and its un-hashed pre-image into any log line that reported an extraction. The
     * pre-image is the worse of the two: it is the dictionary-attackable input whose secrecy is the entire reason the
     * key is fenced from every client-facing surface.
     */
    public record Identity(String key, String preImage, String step, NormalizedAsset asset, MaterialRedaction redaction,
            CryptoAssetIdentityGuard guard, List<String> findings) {

        @Override
        public String toString() {
            return "Identity[step=" + step + ", guard=" + guard + ", assetType="
                    + (asset == null ? null : asset.assetType()) + "]";
        }
    }

    /** Keys a component with no document around it: no reference resolves and nothing is refuted. */
    public Identity of(JsonNode component) {
        return of(component, DocumentScope.none(), Set.of());
    }

    /**
     * Keys a component within its document.
     *
     * @param batchRefutedDigests digests a batch-scoped index found contradicted across documents; empty reduces to
     * document-scoped behaviour
     */
    public Identity of(JsonNode component, DocumentScope scope, Set<String> batchRefutedDigests) {
        AssetNormalizer.Result normalized = normalizer.normalize(component);
        NormalizedAsset asset = normalized.asset();
        JsonNode properties = normalized.redaction().keyedPayload();
        List<String> findings = new ArrayList<>(normalized.redaction().findings());
        // Computed once, before the tier is known: the occurrence tiers hash it, and every tier owes the producer the
        // record of a location that rendered as nothing, since the stored evidence renders it that way whatever tier
        // keyed the row. One pass over the occurrences serves both.
        String triples = Occurrences.triples(component, findings);

        Tier tier = switch (asset.assetType() == null ? "" : asset.assetType()) {
            case CbomNames.ASSET_TYPE_ALGORITHM -> algorithm(asset, properties);
            case CbomNames.ASSET_TYPE_CERTIFICATE ->
                certificate(component, properties, scope, batchRefutedDigests, triples);
            case CbomNames.ASSET_TYPE_PROTOCOL -> protocol(component, properties, scope, triples);
            case CbomNames.ASSET_TYPE_RELATED_CRYPTO_MATERIAL ->
                material(component, properties, normalized.redaction(), triples);
            default -> new Tier(backstop(asset, properties), ChainStep.UNKNOWN_TYPE);
        };
        String preImage = tier.preImage();

        // Applied uniformly to every tier rather than added to each tuple: whether an asset is a claim or an
        // observation is orthogonal to which chain step answered, and one place is one place to review. Appended only
        // for a claim, so an observation keys exactly as it did before this slot existed.
        if (observationMode(component) != null) {
            preImage = preImage + "|" + PreImageSlot.of(CLAIMED);
            asset
                    .note("D0: this asset is a stated CAPABILITY, not an observed deployment, so it keys separately from "
                            + "a scan of the same algorithm");
        }

        recordCaseRisk(tier.caseRiskInputs(), asset);
        return new Identity(IdentityDigests.sha256Hex(preImage), preImage, tier.step().label(), asset,
                normalized.redaction(), guardFor(tier.digestRefuted(), tier.step(), asset), List.copyOf(findings));
    }

    /**
     * One chain step's answer: the pre-image, the step that built it, and the strings the case-risk detector may read.
     *
     * <p>
     * {@code caseRiskInputs} are the pre-image and the strings whose digest alone reaches it -- the distinguished-name
     * composite, the occurrence triples and the cipher-suite token string, whose {@code n:<NAME>} fallback carries a
     * producer's own spelling of a suite. They travel with the tier so the case-risk detector examines exactly what the
     * key consumed, at the site that consumed it, rather than re-deriving it from the component and reading a raw
     * {@code location} the key path had already sanitized. Deliberately absent: the material value behind
     * {@code MAT|..|V|}, the canonical JSON behind a projection digest, and the target algorithm's pre-image behind the
     * {@code A:} discriminator inside the distinguished-name composite. The first is the secret the redaction layer
     * exists to keep out of every carrier; the second is a whole payload, not a spelling an operator could fold; the
     * third is keyed on the target's own row, where its case risk is recorded.
     *
     * <p>
     * A tier whose pre-image spells a value storage withholds lists what may be examined instead of the pre-image: the
     * detector's note is stored in the row's provenance block and can be served, so a withheld value spelled into it is
     * a disclosure. The {@code mat:fingerprint} claim is the one such tier -- see {@link #fingerprintCaseRiskInputs}.
     *
     * <p>
     * {@code digestRefuted} is set only by the certificate tier, so the refutation stays visible outside the method
     * that saw it.
     */
    private record Tier(String preImage, ChainStep step, boolean digestRefuted, List<String> caseRiskInputs) {

        Tier(String preImage, ChainStep step) {
            this(preImage, step, false, List.of(preImage));
        }

        /** A tier whose pre-image carries the digest of {@code hashed}, or nothing more when {@code hashed} is null. */
        static Tier hashing(String preImage, ChainStep step, boolean digestRefuted, String hashed) {
            return new Tier(preImage, step, digestRefuted,
                    hashed == null ? List.of(preImage) : List.of(preImage, hashed));
        }
    }

    /**
     * The safety rule that kept this asset a separate row, or {@code null} when none fired.
     *
     * <p>
     * Ordered by how much the rule constrains a later repair. A refuted digest is the strongest: the evidence actively
     * contradicted a claim, so no alias may absorb the row. A bare-CN subject is next -- the split is permanent by
     * ruling, and no reconciliation path exists. A refuted OID is last: only what the arc would have contributed was
     * discarded, and the arc itself stays stored and auditable.
     */
    private static CryptoAssetIdentityGuard guardFor(boolean digestRefuted, ChainStep step, NormalizedAsset asset) {
        if (digestRefuted) {
            return CryptoAssetIdentityGuard.REFUTED_CERTIFICATE_DIGEST;
        }
        if (step == ChainStep.CRT_CN_ONLY) {
            return CryptoAssetIdentityGuard.BARE_CN_SUBJECT;
        }
        return asset != null && asset.oidConflict() ? CryptoAssetIdentityGuard.REFUTED_OID : null;
    }

    /**
     * The unroutable tier: a component typed cryptographic-asset with an assetType this specification does not know, or
     * with no {@code cryptoProperties} object at all.
     *
     * <p>
     * Such a component is <b>not skipped</b>. The name is part of the key because without it the projection digest of
     * an absent properties object is the SAME for every such component, so every broken asset in the estate collapses
     * into one row whose elected payload is whichever arrived first. That is an over-merge, the direction the
     * prefer-a-visible-split rule exists to forbid.
     */
    private String backstop(NormalizedAsset asset, JsonNode properties) {
        return "RAW|" + PreImageSlot.of(asset.assetType()) + "|" + CanonicalJson.projectionDigest(properties) + "|"
                + PreImageSlot.of(AsciiText.fold(collapse(AsciiText.strip(asset.name()))));
    }

    private Tier algorithm(NormalizedAsset asset, JsonNode properties) {
        if (asset.family() != null) {
            // `primitive` is NOT in the key. Carrying it produced 434 keys where 399 are correct, and 426 assets sat
            // in groups that disagreed with themselves about it: producers describing one RSA-2048 emit
            // {signature, pke, kem}. It stays a stored, indexed, filterable column.
            return new Tier("ALG|" + join(asset.family(), text(asset.parameterSet()), asset.curve(), asset.mode(),
                    asset.padding(), asset.variant()), ChainStep.ALG_FAMILY);
        }
        if (asset.name() != null && !AsciiText.isBlank(asset.name())) {
            // No family derivable, so the normalized name becomes the discriminator. Without it one producer's
            // PRIVATE KEY, RAW and MGF1 collapse into one meaningless family-less row.
            //
            // The token is NOT pre-escaped: the join below escapes every slot, so escaping here produced
            // `private%2520key` -- a percent sign escaped twice. No implementer reading the specification would
            // reproduce that.
            String token = AsciiText.fold(collapse(AsciiText.strip(asset.name())));
            return new Tier("ALG||" + join(token, text(asset.parameterSet()), asset.curve(), asset.mode(),
                    asset.padding(), asset.variant()), ChainStep.ALG_NAME);
        }
        return new Tier("RAW|algorithm|" + CanonicalJson.projectionDigest(properties), ChainStep.ALG_BACKSTOP);
    }

    /**
     * Content hash first, distinguished-name composite last.
     *
     * <p>
     * This inverts the original design, which engineered the composite as primary on the belief that nobody emits
     * component hashes. Measured, {@code component.hashes[]} is present on 6 of 6 real certificate instances and the
     * 1.7-only {@code fingerprint} on 0 of 6, so the content hash is the primary path. Promoting a collision-prone,
     * normalization-dependent key over a content hash present in 100% of the data would be a strict downgrade.
     */
    private Tier certificate(JsonNode component, JsonNode properties, DocumentScope scope,
            Set<String> batchRefutedDigests, String triples) {
        JsonNode certificate = objectOrNull(properties.get(CbomNames.CERTIFICATE_PROPERTIES));
        Set<String> refuted = new TreeSet<>(scope.refutedCertificateDigests());
        refuted.addAll(batchRefutedDigests);

        // Each claimed digest is tried in turn. A refuted one must not suppress a sound one: a producer stamping the
        // same placeholder fingerprint on two certificates may still compute correct, distinct component hashes for
        // both, and falling straight through to the composite would strand them.
        List<String> claimed = CertificateDigests.claimed(component, certificate);
        // Recorded rather than discarded: a row whose digest was refuted must be distinguishable from one that never
        // carried a digest at all, or the alias-repair refusal the guard column exists for cannot be implemented.
        boolean digestRefuted = false;
        for (int index = 0; index < claimed.size(); index++) {
            String digest = claimed.get(index);
            if (refuted.contains(digest)) {
                digestRefuted = true;
                continue;
            }
            boolean fromFingerprint = digest.equals(CertificateDigests.fingerprintDigest(certificate));
            return new Tier("CRT|H|" + SPEC_ID + "|" + PreImageSlot.of(digest),
                    fromFingerprint ? ChainStep.CRT_FINGERPRINT : ChainStep.CRT_COMPONENT_HASH, digestRefuted,
                    List.of());
        }

        String serial = text(certificate, "serialNumber");
        String issuer = DistinguishedNames.normalize(text(certificate, CbomNames.ISSUER_NAME), normalizer.tables());
        // A sentinel serial is an absent one, as it is in every other slot. Keyed, `serialNumber: "unknown"` gave
        // every certificate of an issuer one row -- the over-merge in the severe direction, on a producer spelling the
        // sentinel list exists to name.
        if (serial != null && !AsciiText.isBlank(serial) && !normalizer.tables().isSentinel(serial) && issuer != null) {
            String serialIssuer = "CRT|S|" + SPEC_ID + "|" + PreImageSlot.of(AsciiText.fold(AsciiText.strip(serial)))
                    + "|" + PreImageSlot.of(issuer);
            return new Tier(serialIssuer, ChainStep.CRT_SERIAL_ISSUER, digestRefuted, List.of(serialIssuer));
        }

        String subject = DistinguishedNames.normalize(text(certificate, CbomNames.SUBJECT_NAME), normalizer.tables());
        if (subject != null && issuer != null) {
            String composite = dnPreImage(properties, scope);
            return Tier
                    .hashing("CRT|D|" + SPEC_ID + "|" + IdentityDigests.sha256Hex(composite),
                            ChainStep.CRT_DN_COMPOSITE, digestRefuted, composite);
        }

        String token = ComponentNames.stableToken(text(component, "name"));
        if (subject != null) {
            // Reached when the composite is not constructible -- typically a CN-only subject with no issuer. It gets
            // its own row and is never merged into a full-DN row: two internal CAs both issue CN=localhost, and
            // merging them would make "where is weak crypto deployed" answer CLEAN for a vulnerable host.
            // The occurrence discriminator is appended ONLY when the component has occurrences. Emitting a trailing
            // empty slot re-keys every degenerate certificate.
            String suffix = triples == null ? "" : "|" + IdentityDigests.sha256Hex(triples);
            String validity = validitySlots(certificate);
            ChainStep step = DistinguishedNames.isCommonNameOnly(subject)
                    ? ChainStep.CRT_CN_ONLY
                    : ChainStep.CRT_SUBJECT_ONLY;
            return Tier
                    .hashing("CRT|C|" + SPEC_ID + "|" + PreImageSlot.of(subject) + "|" + validity + "|"
                            + PreImageSlot.of(token) + suffix, step, digestRefuted, triples);
        }
        // The backstop needs the name too: two certificates with no digest, no issuer and no subject --
        // `server-rsa-2048.pem` and `server-ecdsa-p256.pem` in a real document -- merged on a payload hash alone.
        String certificateBackstop = "RAW|certificate|" + PreImageSlot.of(token) + "|"
                + CanonicalJson.projectionDigest(properties);
        return new Tier(certificateBackstop, ChainStep.CRT_BACKSTOP, digestRefuted, List.of(certificateBackstop));
    }

    /**
     * The two {@code CRT|C} validity slots, each escaped as an outer slot.
     *
     * <p>
     * R15 escapes {@code |} inside a slot value and these two were joined raw, which is reachable on schema-valid
     * input: {@link ValidityTimestamps#normalize} returns the stripped producer string when it parses as no timestamp
     * at all, so a producer controls the bytes. Demonstrated, identically in Java and in the reference kernel:
     * {@code ("a|b","c")} and {@code ("a","b|c")} both built {@code CRT|C|v1|<subject>|a|b|c|<token>}.
     *
     * <p>
     * These are outer slots, unlike the same two values inside {@link #dnPreImage}, which keep their spaces because
     * only their digest reaches a slot -- R15 §873, and getting it backwards re-keys every certificate -- and are
     * escaped there against the composite's own delimiter instead. 0 of 8 {@code CRT|C} vectors move, because every
     * validity slot they carry is epoch digits or empty.
     */
    private static String validitySlots(JsonNode certificate) {
        return PreImageSlot.of(ValidityTimestamps.normalize(text(certificate, "notValidBefore"))) + "|"
                + PreImageSlot.of(ValidityTimestamps.normalize(text(certificate, "notValidAfter")));
    }

    /**
     * The five-field string the distinguished-name composite hashes, in order.
     *
     * <p>
     * Published as an operation because the key carries only its digest. One proof-of-concept round could not reproduce
     * this step and tried 768 combinations of spelling, timestamp form and public-key candidate before giving up. A
     * hashed slot must publish its input or it is not testable.
     *
     * <p>
     * The values here are <b>not</b> outer-slot-escaped: only the SHA-256 of this string reaches a slot, so the inner
     * pre-image carries a space intact where an outer slot would carry {@code %20} -- R15 §873, and 11 of the 14
     * ratified composites carry a space, so applying the outer set here would re-key them all. What each value
     * <em>is</em> escaped against is this string's own delimiter, through {@link #compositeField}: the five fields were
     * joined raw, and {@link ValidityTimestamps#normalize} hands back an unparseable producer value verbatim, so
     * {@code (notBefore="a|b", notAfter="c")} and {@code (notBefore="a", notAfter="b|c")} built one composite and one
     * key. The same raw join let an observation {@code (notAfter="2|t", name="claimed")} render as a claimed
     * certificate {@code (notAfter="2", name="t")}, forging the D0 marker. Every field goes through the escape, not
     * only the validity pair: the distinguished-name halves happen to backslash their own {@code |} today, but a
     * composition is injective on its own terms or not at all.
     */
    public String dnPreImage(JsonNode properties, DocumentScope scope) {
        JsonNode certificate = objectOrNull(properties.get(CbomNames.CERTIFICATE_PROPERTIES));
        return String
                .join("|",
                        compositeField(DistinguishedNames
                                .normalize(text(certificate, CbomNames.SUBJECT_NAME), normalizer.tables())),
                        compositeField(DistinguishedNames
                                .normalize(text(certificate, CbomNames.ISSUER_NAME), normalizer.tables())),
                        compositeField(ValidityTimestamps.normalize(text(certificate, "notValidBefore"))),
                        compositeField(ValidityTimestamps.normalize(text(certificate, "notValidAfter"))),
                        compositeField(publicKeyDigest(properties, scope)));
    }

    /**
     * One field of the distinguished-name composite, escaped against the composite's own {@code |} and nothing else.
     *
     * <p>
     * The escape set is this string's, not {@link PreImageSlot}'s, for the same reason {@link #fingerprintClaim} owns
     * its {@code :}: the outer set would also escape the spaces the ratified composites carry intact. {@code %} is in
     * the set because an escape that leaves its own escape character alone is not injective -- {@code a%7Cb} and
     * {@code a|b} would render one field.
     */
    private static String compositeField(String value) {
        return value == null ? "" : PreImageSlot.escape(value, CryptoAssetIdentity::compositeEscapeFor);
    }

    private static String compositeEscapeFor(char character) {
        return switch (character) {
            case '%' -> "%25";
            case '|' -> "%7C";
            default -> null;
        };
    }

    /**
     * Identifies the certificate's public key by CONTENT, never by its bom-ref.
     *
     * <p>
     * A bom-ref is producer-assigned and document-scoped: the same certificate's {@code subjectPublicKeyRef} pointed at
     * an <em>algorithm</em> component on one branch of a producer and at the <em>public key</em> component on another,
     * so hashing the ref string would make identity depend on which build emitted the document.
     *
     * <p>
     * Two tiers, because refusing an algorithm target outright produced a wrong merge in real data: an nginx example
     * carries two self-signed certificates with identical subject, issuer and validity whose only difference is that
     * one points at an RSA-2048 algorithm and the other at an ECDSA-P256 one. Returning nothing for both collapsed two
     * genuinely different certificates into one row.
     *
     * <p>
     * <b>What this method contributes to that.</b> It resolves the reference naming this certificate's public key,
     * preferring a 1.7 related-asset entry over the 1.6 field.
     *
     * <p>
     * The entry's type is separator-dropped and ASCII-folded, the same reduction the asset-type router applies to
     * producer text. Against two raw literals, {@code PublicKey} and {@code public_key} matched neither, so the ref
     * stayed the 1.6-only {@code subjectPublicKeyRef}, resolved to nothing, and two certificates pointing at different
     * public keys both got an empty slot -- the over-merge the two key tiers exist to prevent. Not
     * {@code normalizeAssetType}: this is a related-asset type, which that router does not know.
     *
     * <p>
     * <b>Two public-key entries name nothing.</b> Taking the first one made array order decide the certificate's
     * identity: transposing two {@code public-key} entries with different targets moved the key, one level below the
     * rule that a duplicated {@code bom-ref} resolves to nothing because document order cannot be allowed to decide
     * identity. An array inside a component is a different serialization of one document exactly as a permutation of
     * its components is, so the same arm applies -- more than one entry folding to {@code publickey} is an unresolved
     * reference, and the 1.6 field is not consulted in its place, since the array did state the key and stated it
     * ambiguously. 0 corpus certificates carry two such entries, so nothing moves today.
     *
     * <p>
     * Takes the certificate node nullable and tests it here rather than being handed a proven-present one, so the
     * absence of {@code certificateProperties} is answered in one place instead of at every call.
     */
    private static JsonNode subjectPublicKeyRef(JsonNode certificate) {
        if (certificate == null) {
            return null;
        }
        JsonNode related = certificate.get("relatedCryptographicAssets");
        if (related != null && related.isArray()) {
            JsonNode publicKey = null;
            int publicKeys = 0;
            for (JsonNode entry : related) {
                JsonNode type = entry.isObject() ? entry.get("type") : null;
                String entryType = type != null && type.isTextual() ? AsciiText.lookupKey(type.textValue()) : null;
                if (PUBLIC_KEY_REFERENCE.equals(entryType)) {
                    publicKey = entry.get("ref");
                    publicKeys++;
                }
            }
            if (publicKeys > 1) {
                return null;
            }
            if (publicKeys == 1) {
                return publicKey;
            }
        }
        return certificate.get("subjectPublicKeyRef");
    }

    /**
     * Whether a node carries content, which is stricter than carrying a value.
     *
     * <p>
     * Kept here rather than borrowed from the digest helpers: it guards this tier's fingerprint branch and nothing
     * else, and a package-private helper on another class is one deletion away from taking this branch with it.
     *
     * <p>
     * <b>Textual, not merely non-empty.</b> {@code asText()} renders a boolean and a number, so {@code content: 10}
     * keyed identically to {@code content: "10"} and {@code content: true} keyed as the string {@code true} -- two
     * producers stating different things onto one row. Both schema versions type the member as a string, so this is
     * schema-invalid input rather than a live shape, which is why it is a gate and not a finding; the certificate side
     * of the same class already gates on {@code isTextual()}.
     */
    private static boolean hasContent(JsonNode node) {
        return node != null && node.isTextual() && !AsciiText.isBlank(node.textValue());
    }

    /**
     * Joins a fingerprint's algorithm to its content so neither half can forge the boundary between them.
     *
     * <p>
     * The second site of one class. {@code CertificateDigests.claim} closed it for {@code hashes[]} and
     * {@code fingerprint} on the certificate side; this pre-image kept the bare {@code :}, so
     * {@code {"alg":"sha-256:a","content":"b"}} and {@code {"alg":"sha-256","content":"a:b"}} rendered one string and
     * two different keys became one. Relocating the ticket item with the certificate file moved the item and left the
     * class behind.
     *
     * <p>
     * The escape set is this layer's, not {@link PreImageSlot}'s: the joined claim then enters a {@code |}-delimited
     * outer slot, and teaching {@code PreImageSlot} the {@code :} would escape it there too and erase the boundary it
     * exists to draw. So the pre-image carries the doubly-escaped {@code %253A}, exactly as the certificate claim does.
     *
     * <p>
     * <b>A blank algorithm is an absent one.</b> {@code "alg": ""} folded to the empty label and keyed
     * {@code F|:content} where an absent {@code alg} keys {@code F|unknown:content}; a producer emitting the member
     * empty has stated no algorithm, which is what {@code unknown} already means. Emptiness rather than nullness is the
     * same rule the content gate above uses.
     *
     * <p>
     * <b>Both halves strip before they fold</b>, because the gate above already does. {@link #hasContent} calls
     * surrounding whitespace nothing -- {@code content: "   "} is absent -- while the keyed value kept it, so
     * {@code content: " abc "} keyed {@code %20abc%20} and split from {@code "abc"}, and the gate and the key disagreed
     * about what a space means. Stripping matches {@code mat:id} one tier below and the serial in
     * {@code crt:serial+issuer}. 0 of the 447 fingerprints in {@code cbom-corpus-2026-08-18-r2} (443 on
     * {@code private-key}, 4 on {@code public-key}) and 0 vectors carry a padded half, so nothing moves. What is
     * <em>not</em> closed here is alias canonicalization: {@code SHA256} and {@code SHA-256} are still two labels,
     * which needs the ratified alias source {@code CertificateDigests.canonicalLabel} reads and is open on core#2165.
     */
    private static String fingerprintClaim(JsonNode algorithm, JsonNode content) {
        return PreImageSlot
                .of(PreImageSlot.escape(fingerprintLabel(algorithm), CryptoAssetIdentity::claimEscapeFor) + ":"
                        + PreImageSlot
                                .escape(AsciiText.fold(AsciiText.strip(content.textValue())),
                                        CryptoAssetIdentity::claimEscapeFor));
    }

    /** The algorithm half of a fingerprint claim as the key reads it: stripped and folded, or {@code unknown}. */
    private static String fingerprintLabel(JsonNode algorithm) {
        return algorithm == null || !algorithm.isTextual() || AsciiText.isBlank(algorithm.textValue())
                ? "unknown"
                : AsciiText.fold(AsciiText.strip(algorithm.textValue()));
    }

    /**
     * What the case-fold twin detector may read on the fingerprint tier: the pre-image when storage serves the
     * fingerprint, and the type and algorithm slots alone when storage withholds it.
     *
     * <p>
     * The claim spells {@code content} literally and the tier is open to low-entropy material, so a producer that puts
     * non-hex cleartext under {@code fingerprint.content} on a {@code password} row has put the password in the
     * pre-image. The detector's note is stored in the row's provenance block and can be served, so reading the
     * pre-image there published the cleartext's cased characters -- the same class of leak as reading a raw occurrence
     * location, with the fingerprint as the source. Reading the type slot alone closed that and blinded the detector on
     * the whole tier: a case-fold twin in the algorithm label, or in the content of a {@code private-key} row whose
     * fingerprint is a hex digest and is stored verbatim, keyed apart with nothing recorded, which is exactly what
     * {@link NormalizedAsset#asciiCaseRisk()} promises to record.
     *
     * <p>
     * The line between the two is drawn by what storage serves, not by a type list of this method's own. Where the
     * stored payload carries the fingerprint object, every character of the claim is already served, so a note naming
     * some of its cased characters discloses nothing the row does not; where storage drops the fingerprint --
     * {@code MaterialRedaction} withholds it on every type whose digest it will not publish -- the content is withheld
     * from the detector too, and only the type and the algorithm label are read. The label is producer metadata for the
     * hash, {@code sha-256} on all 447 corpus fingerprints, and is never the material. Deriving the line from the
     * stored payload rather than restating the type list means a storage rule that withholds more tomorrow withholds it
     * from the note in the same change.
     */
    private static List<String> fingerprintCaseRiskInputs(String kind, JsonNode fingerprint,
            MaterialRedaction redaction, String preImage) {
        if (storesFingerprint(redaction)) {
            return List.of(preImage);
        }
        return List.of(PreImageSlot.of(kind), fingerprintLabel(fingerprint.get("alg")));
    }

    /** True when the stored payload carries the material's fingerprint object, so its content is already served. */
    private static boolean storesFingerprint(MaterialRedaction redaction) {
        JsonNode material = objectOrNull(redaction.storedPayload().get(CbomNames.RELATED_CRYPTO_MATERIAL_PROPERTIES));
        JsonNode fingerprint = material == null ? null : material.get("fingerprint");
        return fingerprint != null && fingerprint.isObject();
    }

    private static String claimEscapeFor(char character) {
        return switch (character) {
            case '%' -> "%25";
            case ':' -> "%3A";
            default -> null;
        };
    }

    private String publicKeyDigest(JsonNode properties, DocumentScope scope) {
        JsonNode target = scope
                .resolve(subjectPublicKeyRef(objectOrNull(properties.get(CbomNames.CERTIFICATE_PROPERTIES))));
        if (target == null) {
            return null;
        }
        JsonNode targetProperties = objectOrNull(target.get("cryptoProperties"));
        JsonNode material = targetProperties == null
                ? null
                : objectOrNull(targetProperties.get(CbomNames.RELATED_CRYPTO_MATERIAL_PROPERTIES));
        JsonNode value = material == null ? null : material.get("value");
        // Textual and blank-checked, the same guard CertificateDigests carries for the same reason: asText() on an
        // object or an array yields the empty string rather than null, so a target carrying `{"sha256": {}}` used to
        // contribute the discriminator `K:` -- and two certificates with equal DN and validity pointing at two
        // DIFFERENT such targets then merged. Worse than an empty slot, because returning here also skipped the
        // target-identity fallback below, which does discriminate. A boolean or numeric sha256 keyed on "true" or "5"
        // by the same route.
        JsonNode keyDigest = value != null && value.isObject() ? value.get("sha256") : null;
        if (keyDigest != null && keyDigest.isTextual()) {
            // Folded and stripped before the blank check, the way CertificateDigests reads a content digest. The
            // textual branch below renders lowercase hex through MaterialValueDigest, so an uppercase spelling of the
            // same digest keyed apart from it until this fold.
            String digest = AsciiText.fold(AsciiText.strip(keyDigest.textValue()));
            if (!digest.isEmpty()) {
                return "K:" + digest;
            }
        }
        if (value != null && value.isTextual() && !AsciiText.isBlank(value.textValue())) {
            try {
                return "K:" + MaterialValueDigest.of(value.textValue());
            } catch (IllegalArgumentException e) {
                // Contained here rather than propagated. The refusal belongs to the TARGET component, which becomes
                // its own reported skip; letting it escape made one malformed key component silently remove every
                // certificate that referenced it from the inventory. The certificate falls through to the tier
                // below, which still discriminates by the target's own identity.
            }
        }
        // No key material on the target. Identify it by its own normalized identity so the composite still
        // discriminates, rather than degrading to an empty slot.
        // Normalized, not raw -- the same rule the router applies. A raw comparison let a target spelled
        // `Algorithm` route as an algorithm for its own row while contributing no discriminator here, so
        // capitalization alone moved the certificate's identity.
        String targetType = normalizer.normalizeAssetType(text(targetProperties, "assetType"));
        if (CbomNames.ASSET_TYPE_ALGORITHM.equals(targetType)) {
            try {
                AssetNormalizer.Result targetNormalized = normalizer.normalize(target);
                return "A:" + IdentityDigests
                        .sha256Hex(algorithm(targetNormalized.asset(), targetNormalized.redaction().keyedPayload())
                                .preImage());
            } catch (IllegalArgumentException e) {
                // Same containment as the value tier above: a malformed target must cost the target its row, never
                // the certificates pointing at it.
            }
        }
        return null;
    }

    private Tier protocol(JsonNode component, JsonNode properties, DocumentScope scope, String triples) {
        JsonNode protocol = objectOrNull(properties.get("protocolProperties"));
        String rawKind = text(protocol, "type");
        String kind = rawKind == null || AsciiText.isBlank(rawKind) ? null : AsciiText.fold(AsciiText.strip(rawKind));
        String version = normalizeProtocolVersion(text(protocol, "version"));
        String suiteTokens = CipherSuites.tokens(properties, scope.refutedSuiteCodes());
        String configuration = protocolConfiguration(text(component, "name"));
        // Appended only when it carries something. An empty slot that still contributes a separator would re-key
        // every protocol row in the estate for no change in meaning -- 120 of 145 corpus rows.
        String suffix = configuration == null ? "" : "|" + PreImageSlot.of(configuration);

        if (kind != null && version != null && suiteTokens != null) {
            return Tier
                    .hashing(
                            "PRT|" + PreImageSlot.of(kind) + "|" + PreImageSlot.of(version) + "|"
                                    + IdentityDigests.sha256Hex(suiteTokens) + suffix,
                            ChainStep.PRT_TYPE_VERSION_SUITES, false, suiteTokens);
        }
        // Tier 2 is for a row that offered NO suites. A row that declared suites which could not be resolved falls to
        // the name tier instead, so "we know it has suites and cannot read them" never merges with "nothing was said".
        // Without the guard, tier 2 fired for every versioned row and the name tier below was unreachable.
        if (kind != null && version != null && !CipherSuites.declared(properties)) {
            return new Tier("PRT|" + PreImageSlot.of(kind) + "|" + PreImageSlot.of(version) + suffix,
                    ChainStep.PRT_TYPE_VERSION);
        }
        if (kind != null) {
            return protocolBelowSuiteDigest(component, properties, kind, version, suffix, triples);
        }
        // The name is in the key, mirroring the unknown-type backstop. Two type-less protocol components with
        // byte-identical properties and different names used to merge. Stated precisely: the same name at different
        // occurrence locations still merges here, exactly as it does on the tier this mirrors.
        String rawName = text(component, "name");
        return new Tier(
                "RAW|protocol|" + CanonicalJson.projectionDigest(properties) + "|"
                        + PreImageSlot.of(AsciiText.fold(collapse(AsciiText.strip(rawName == null ? "" : rawName)))),
                ChainStep.PRT_BACKSTOP);
    }

    /**
     * The tiers a protocol row reaches once no suite digest resolved, in descending order of what discriminates it.
     *
     * <p>
     * Below the suite digest the NAME carries the discriminating information. Three different TLS suites modelled as
     * protocol assets collapsed onto ONE identity because they share a type, carry no version and no
     * {@code cipherSuites} array, and sit at the same occurrence.
     */
    private Tier protocolBelowSuiteDigest(JsonNode component, JsonNode properties, String kind, String version,
            String suffix, String triples) {
        String token = ComponentNames.stableToken(text(component, "name"));
        if (version != null && !token.isEmpty()) {
            return new Tier(
                    "PRT|" + PreImageSlot.of(kind) + "|" + PreImageSlot.of(version) + "|N:" + PreImageSlot.of(token),
                    ChainStep.PRT_TYPE_VERSION_NAME);
        }
        if (triples != null) {
            // The version slot is carried here for the same reason the terminal branch below carries it: this tier is
            // reached with a version in hand whenever the name token is empty, and emitting the slot empty gave an
            // SSL 3.0 endpoint and a TLS 1.3 endpoint at one location a single identity -- the hazard tier 2 exists
            // to separate, live one tier down. 0 corpus rows carry a version, no name and an occurrence together, so
            // nothing moves today.
            return Tier
                    .hashing(
                            "PRT|" + PreImageSlot.of(kind) + "|" + (version == null ? "" : PreImageSlot.of(version))
                                    + "|" + PreImageSlot.of(token) + "|" + IdentityDigests.sha256Hex(triples),
                            ChainStep.PRT_TYPE_OCCURRENCE, false, triples);
        }
        if (!token.isEmpty()) {
            return new Tier("PRT|" + PreImageSlot.of(kind) + "||" + PreImageSlot.of(token), ChainStep.PRT_TYPE_NAME);
        }
        // Terminal fall-through. The version slot is carried and emitted even when empty, which makes the shape
        // regular against tier 1 -- it used to be dropped, so TLS 1.2, TLS 1.3 and a version-less row all shared one
        // identity in the nameless case. It also carries the suites-declared marker, without which the version-less
        // case still merged the two states tier 2 exists to separate. `declared` is a closed token and cannot collide
        // with the digest this slot otherwise holds, because a digest is hex.
        String declared = CipherSuites.declared(properties) ? "declared" : "";
        return new Tier("PRT|" + PreImageSlot.of(kind) + "|" + (version == null ? "" : PreImageSlot.of(version)) + "|"
                + declared + suffix, ChainStep.PRT_TYPE_ONLY);
    }

    /**
     * {@code TLSv1.3}, {@code TLS 1.3} and {@code 1.3} all become {@code 1.3}; sentinels become absent.
     *
     * <p>
     * A producer can emit {@code version: "n/a"} -- its parser returns that string on unknown input and the caller does
     * not guard -- which would otherwise grow a permanent {@code PRT|tls|n/a} bucket alongside the real one.
     */
    public String normalizeProtocolVersion(String raw) {
        if (raw == null || normalizer.tables().isSentinel(raw)) {
            return null;
        }
        String stripped = AsciiText.strip(raw);
        String text = AsciiText.strip(PROTOCOL_PREFIX.matcher(stripped).replaceFirst(""));
        if (!text.equals(stripped) && TWO_DIGITS.matcher(text).matches()) {
            // The compressed spelling: `TLS12` is TLS 1.2, not version 12. Reading it as a whole number stored a
            // nonsense version AND split the asset from the `1.2` bucket every other spelling lands in. Scoped to a
            // name that actually carried a protocol prefix, so a bare `12` is still whatever the producer meant.
            return text.charAt(0) + "." + text.charAt(1);
        }
        if (ALL_DIGITS.matcher(text).matches()) {
            return text + ".0";
        }
        return AsciiText.isDottedDigits(text, 1) ? text : null;
    }

    /**
     * The identity-bearing part of a protocol component's name: posture, then port.
     *
     * <p>
     * Both discriminators are deliberately closed rather than free text, because a free-text residue over-splits. A
     * label outside these two shapes still merges, which is what keeps {@code TLS 1} beside {@code TLSv1.0} and
     * {@code JDK TLS 1.2} beside {@code TLSv1.2} -- while keeping a posture claim ({@code (CNSA 2.0)} against
     * {@code (PQC)}) and an endpoint (three ports collapsed into one row) apart.
     */
    public String protocolConfiguration(String name) {
        if (name == null || AsciiText.isBlank(name)) {
            return null;
        }
        String folded = AsciiText.fold(name);
        TreeSet<String> parts = new TreeSet<>();
        POSTURE_TOKENS.forEach((spelling, token) -> {
            if (folded.contains(spelling)) {
                parts.add(token);
            }
        });
        TreeSet<String> ports = new TreeSet<>();
        Matcher matcher = ENDPOINT_PORT.matcher(folded);
        while (matcher.find()) {
            ports.add(matcher.group(1));
        }
        List<String> ordered = new ArrayList<>(parts);
        ordered.addAll(ports);
        return ordered.isEmpty() ? null : String.join(",", ordered);
    }

    /**
     * Identity for key material. In practice the fallback IS the identity function.
     *
     * <p>
     * Measured: the primary chain -- id, fingerprint, value digest -- fires on 8 of 51 real material assets. One
     * producer emits {@code {"type": "secret-key"}} and nothing else for all 37 of its assets, so 84% reach the
     * occurrence tier.
     */
    private Tier material(JsonNode component, JsonNode properties, MaterialRedaction redaction, String triples) {
        JsonNode material = objectOrNull(properties.get(CbomNames.RELATED_CRYPTO_MATERIAL_PROPERTIES));
        String rawKind = text(material, "type");
        String kind = AsciiText.fold(AsciiText.strip(rawKind == null ? "" : rawKind));

        // Content-derived tiers first. `id` is a PRODUCER LABEL, not a global identifier: real corpora carry both a
        // UUID stable across documents and hand-written labels like `server-key-2024`, and nothing distinguishes the
        // two. Two different keys can share an id, so it must never outrank a fingerprint or a value digest.
        JsonNode fingerprint = material == null ? null : material.get("fingerprint");
        // Blankness, not nullness: a content string of `""` -- or of a space, which folds to the same nothing and
        // which `isEmpty` admitted -- made every such component key as `MAT|<kind>|F|unknown:%20`, so two different
        // secret keys collapsed onto one row and the value-hash tier one branch below, which would have kept them
        // apart, was never reached. Blank is the reference whitespace set, as it is in every other slot.
        if (fingerprint != null && fingerprint.isObject() && hasContent(fingerprint.get(CbomNames.CONTENT))) {
            String preImage = "MAT|" + PreImageSlot.of(kind) + "|F|"
                    + fingerprintClaim(fingerprint.get("alg"), fingerprint.get(CbomNames.CONTENT));
            return new Tier(preImage, ChainStep.MAT_FINGERPRINT, false,
                    fingerprintCaseRiskInputs(kind, fingerprint, redaction, preImage));
        }
        if (redaction.identityDigest() != null) {
            return new Tier("MAT|" + PreImageSlot.of(kind) + "|V|" + redaction.identityDigest(),
                    ChainStep.MAT_VALUE_HASH);
        }
        String identifier = text(material, "id");
        if (identifier != null && !AsciiText.isBlank(identifier)) {
            return new Tier("MAT|" + PreImageSlot.of(kind) + "|I|" + PreImageSlot.of(AsciiText.strip(identifier)),
                    ChainStep.MAT_ID);
        }

        // Below the content-derived tiers the type slot may carry nothing at all -- `other` is a catch-all -- so the
        // stable part of the name joins the discriminator. That is what keeps a CRL and a CSR apart.
        String token = ComponentNames.stableToken(text(component, "name"));
        if (triples != null) {
            return Tier
                    .hashing("MAT|" + PreImageSlot.of(kind) + "|O|" + PreImageSlot.of(token) + "|"
                            + IdentityDigests.sha256Hex(triples), ChainStep.MAT_OCCURRENCE, false, triples);
        }
        return new Tier("MAT|" + PreImageSlot.of(kind) + "|P|" + PreImageSlot.of(token) + "|"
                + CanonicalJson.projectionDigest(properties), ChainStep.MAT_BACKSTOP);
    }

    /**
     * {@code "claimed"} when a document marks this asset as a capability rather than an observed deployment.
     *
     * <p>
     * A vendor's "this product supports post-quantum crypto" and an operator's scan of a box that is not running it are
     * different facts about different things, and the merge rule -- richest description wins -- let the brochure
     * overwrite the scan. CycloneDX has no native field for this, so the signal comes from a marker property, and until
     * a producer emits one every asset is an observation and every key is unchanged.
     */
    public String observationMode(JsonNode component) {
        JsonNode properties = component == null ? null : component.get("properties");
        if (properties == null || !properties.isArray()) {
            return null;
        }
        for (JsonNode entry : properties) {
            if (!entry.isObject()) {
                continue;
            }
            JsonNode name = entry.get("name");
            JsonNode value = entry.get("value");
            if (name != null && name.isTextual() && CLAIM_PROPERTY.matcher(name.textValue()).find() && value != null
                    && value.isTextual() && CLAIM_VALUES.contains(AsciiText.fold(AsciiText.strip(value.textValue())))) {
                return CLAIMED;
            }
        }
        return null;
    }

    /**
     * Records that this row carries a value the ASCII fold left unfolded, over exactly the bytes the key consumed.
     *
     * <p>
     * The detector reads the pre-image and the inner strings it hashed, never a per-step re-derivation from the
     * component. The re-derivation read {@code evidence.occurrences[].location} raw, so a credential the key path had
     * stripped through {@code Occurrences.sanitizeLocation} landed in {@link NormalizedAsset#keyedCaseValues} and its
     * accented letters in a served note -- while the key and the stored evidence carried neither; and it flagged a
     * {@code CRT|H} certificate for a distinguished name that tier never hashes. Reading what was hashed makes both
     * impossible by construction rather than by keeping a step table in sync with the tiers. The escapes change no
     * non-ASCII character, so the detector sees the same cased letters the hash did.
     *
     * <p>
     * This is provenance, not a claim that a duplicate exists: whether one does is a question about the estate, which
     * only a batch-scoped detector can answer.
     */
    private static void recordCaseRisk(List<String> keyed, NormalizedAsset asset) {
        asset.setKeyedCaseValues(keyed);
        asset.setAsciiCaseRisk(unfoldedCaseRisk(keyed));
        if (!asset.asciiCaseRisk().isEmpty()) {
            // Worded to avoid naming the key: this note is stored in the row's provenance block and can be served,
            // and the exposure fence refuses a production source outside persistence that names the key at all.
            asset
                    .note("R12: non-ASCII cased characters " + String.join("", asset.asciiCaseRisk())
                            + " are keyed unfolded; the case-fold twin detector examines this row");
        }
    }

    /**
     * Non-ASCII cased characters found in values that reach the identity key.
     *
     * <p>
     * Their presence means this asset may hold a duplicate row that a Unicode-folding implementation would have merged
     * -- a deliberate trade, since a stable duplicate beats an unstable merge, but one an operator must be able to SEE
     * rather than discover as an unexplained near-duplicate.
     */
    public static List<String> unfoldedCaseRisk(List<String> values) {
        // Code-point order, like every other ordered sequence in this package. Natural String order puts an astral
        // cased character below a BMP one at or above U+E000, so the R12 provenance note listed them in an order the
        // reference does not use. No key moves -- the note is not keyed.
        TreeSet<String> found = new TreeSet<>(AsciiText.BY_CODE_POINT);
        for (String value : values) {
            if (value == null) {
                continue;
            }
            value
                    .codePoints()
                    .filter(codePoint -> codePoint > 127)
                    .filter(codePoint -> Character.toLowerCase(codePoint) != Character.toUpperCase(codePoint))
                    .forEach(codePoint -> found.add(new String(Character.toChars(codePoint))));
        }
        return List.copyOf(found);
    }

    private static String join(String... slots) {
        StringBuilder joined = new StringBuilder();
        for (int index = 0; index < slots.length; index++) {
            if (index > 0) {
                joined.append('|');
            }
            joined.append(PreImageSlot.of(slots[index]));
        }
        return joined.toString();
    }

    /**
     * Whitespace runs in a keyed name collapse to one space, over the reference whitespace set. A double ASCII space
     * was the only run collapsed before, so {@code a<TAB>b} and a no-break space keyed apart from the plain-space
     * spelling on the three name-keyed tiers -- and the unknown-type backstop did not strip at all.
     */
    private static String collapse(String value) {
        return value == null ? "" : AsciiText.collapseWhitespace(value);
    }

    private static String text(Integer value) {
        return value == null ? null : value.toString();
    }

    private static String text(JsonNode node, String field) {
        if (node == null) {
            return null;
        }
        JsonNode value = node.get(field);
        return value != null && value.isTextual() ? value.textValue() : null;
    }

    private static JsonNode objectOrNull(JsonNode node) {
        return node != null && node.isObject() ? node : null;
    }
}
