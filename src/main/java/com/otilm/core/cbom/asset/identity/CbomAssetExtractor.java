package com.otilm.core.cbom.asset.identity;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.otilm.core.cbom.asset.OccurrenceEvidenceCapper;
import com.otilm.core.model.cbom.CryptoAssetIdentityGuard;
import com.otilm.core.serialization.ObjectMapperFactory;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Deque;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * Walks a CycloneDX document's component tree and extracts every cryptographic asset it carries.
 *
 * <p>
 * Version-agnostic by construction. Nothing here reads {@code specVersion}: 1.6 and 1.7 differ in field <em>names</em>
 * -- {@code curve} became {@code ellipticCurve}, and every reference field was renamed -- and those differences are
 * absorbed by the normalizer reading both spellings and by the hashed projection stripping references before any
 * digest. A walker that branched on the declared version would have to be right about a value producers get wrong: one
 * really does ship {@code specVersion} as the number {@code 999}.
 *
 * <p>
 * <b>Nothing a producer can write makes this throw.</b> A component that cannot be keyed is reported as a skip and the
 * walk continues, because one malformed asset must not cost an operator the other four thousand. The skips are values,
 * not log lines: a document is untrusted input, and a walker that logged what it could not parse would print
 * pre-redaction content into an appender the redaction proof does not cover.
 */
public final class CbomAssetExtractor {

    /**
     * How deep a component tree may nest before the walk stops descending.
     *
     * <p>
     * Set to match the JSON parser's own default nesting limit, and that is the point: the parser refuses a document
     * nested deeper than this before the walker ever sees it, so nothing that parses can be truncated here. A tighter
     * bound would silently drop real assets out of a document the parser accepted, which is data loss dressed as
     * robustness -- measured the hard way, with a bound of 64 that would have discarded everything below it.
     *
     * <p>
     * The walk is iterative regardless, so depth costs heap rather than stack. {@code components} nests arbitrarily in
     * both schema versions, and a recursive descent over a deep document would exhaust the stack and take the whole
     * ingest with it -- a denial of service costing one small file.
     */
    private static final int MAX_DEPTH = 1000;

    private static final ObjectMapper MAPPER = ObjectMapperFactory.storage();

    private static final TypeReference<Map<String, Object>> MAP_TYPE = new TypeReference<>() {
    };

    private final CryptoAssetIdentity identity;

    public CbomAssetExtractor(CryptoAssetIdentity identity) {
        this.identity = identity;
    }

    /**
     * One asset that was extracted, with everything the persistence layer needs to store it.
     *
     * <p>
     * <b>The raw component is deliberately not here.</b> An earlier shape carried it beside the redacted payload, which
     * quietly undid the one property redaction exists for: the plaintext is dropped before identity, persistence,
     * logging or metrics can observe it, and handing the caller the original node put it back within reach of all four.
     * It cost nothing to notice and everything to miss -- a record's generated {@code toString} alone would have
     * printed inlined key material into any log that reported an extraction.
     *
     * <p>
     * {@code retainedProperties} is the redacted payload, which is what {@code crypto_asset_source} stores.
     *
     * <p>
     * {@code guard} is the safety rule that forced this asset to stay its own row, or {@code null} when none fired. It
     * is published here because the alias-repair path has to refuse an alias where a safety rule caused the split, and
     * two of the three signals are visible only inside the tier that produced the key.
     *
     * <p>
     * {@code findings} carries what the pipeline has to tell the producer -- a dropped value, a withheld digest, an
     * inlined secret, a dropped extension, an occurrence whose stated location rendered as no location. It is published
     * because {@code MaterialRedaction.findings()} had no reader anywhere: the values were computed, and then died at
     * this boundary, so a promise the redaction class makes in its own Javadoc was unreachable the moment extraction
     * returned. Carrying them here does not report them -- core#2073 owns the per-CBOM reporting path -- but it turns
     * that work into wiring an existing value rather than re-deriving it, and it makes the gap visible to anyone
     * reading this record.
     *
     * <p>
     * <b>{@code identityKey}, and this file is allowlisted for that vocabulary.</b> The component was called
     * {@code key} so the exposure fence's regex would not see it -- which worked, and was the wrong shape: a production
     * source routing <em>around</em> a fence is invisible to the next reader, where an allowlist entry is a reviewed
     * record that this file carries the value on purpose. It does carry it: this record is how the keyed asset reaches
     * the persistence path. The entry exempts only the stored-value vocabulary, so a pre-image spelling here still
     * fails, and the logging rule carries no allowlist at all -- which is why the {@code toString} override below is
     * still the thing that keeps the value out of a log line.
     */
    public record ExtractedAsset(String identityKey, String chainStep, NormalizedAsset normalized, String componentName,
            JsonNode retainedProperties, List<Map<String, Object>> evidence, int reportedOccurrences,
            CryptoAssetIdentityGuard guard, List<String> findings) {

        /**
         * Omits the identity key. The generated {@code toString} would print it, and a record is printed by anything
         * that logs the value or a collection holding it -- including {@link Extraction}, whose own generated
         * {@code toString} recurses into this one. The fence's logging rule has no allowlist, so this file may name the
         * value and may not log it: this override is what makes that true rather than merely stated.
         */
        @Override
        public String toString() {
            return "ExtractedAsset[componentName=" + componentName + ", chainStep=" + chainStep + ", guard=" + guard
                    + ", reportedOccurrences=" + reportedOccurrences + "]";
        }
    }

    /**
     * One component that could not be extracted, and why.
     *
     * <p>
     * The reason names the failure class and the component's own name, never the payload. A skip that quoted what it
     * could not parse would be a disclosure channel for exactly the documents least worth trusting.
     */
    public record Skip(String componentName, String reason) {
    }

    /**
     * Everything a document yielded: the assets, and the components that could not be turned into assets.
     *
     * <p>
     * {@code documentScopeUnavailable} records that the whole-document scope could not be built and the walk ran
     * without it. That is not the recoverable direction: with nothing refuted a fabricated placeholder digest is
     * trusted, and with no reference resolving every certificate's public-key slot empties -- both over-merges. It is
     * recorded here because a caller reading only the assets would see rows and no sign of what they lack.
     */
    public record Extraction(List<ExtractedAsset> assets, List<Skip> skips, boolean depthLimitReached,
            boolean documentScopeUnavailable) {

        public int assetCount() {
            return assets.size();
        }
    }

    /** Extracts with document scope only. Equivalent to passing no batch-scoped refutations. */
    public Extraction extract(JsonNode document) {
        return extract(document, Set.of());
    }

    /**
     * Extracts every cryptographic asset in the document.
     *
     * <p>
     * Output order is document order, and that is a convenience for a reader rather than a guarantee anything depends
     * on: an asset's identity is a function of the asset alone, so permuting the components -- or the documents --
     * cannot change which rows result or what they are keyed as.
     *
     * @param batchRefutedDigests certificate digests a batch-scoped index found contradicted <em>across</em> documents;
     * empty reduces to document-scoped refutation
     */
    public Extraction extract(JsonNode document, Set<String> batchRefutedDigests) {
        if (document == null || !document.isObject()) {
            return new Extraction(List.of(), List.of(), false, false);
        }
        Set<String> refuted = batchRefutedDigests == null ? Set.of() : batchRefutedDigests;

        DocumentScope scope;
        boolean scopeUnavailable = false;
        try {
            scope = DocumentScope.of(document, identity.normalizer());
        } catch (RuntimeException e) {
            // The scope is a whole-document derivation, so a failure here is not attributable to one component. The
            // walk still runs with nothing refuted and no reference resolving -- see Extraction for why that is the
            // over-merging direction, and why it is recorded rather than only survived.
            scope = DocumentScope.none();
            scopeUnavailable = true;
        }

        List<ExtractedAsset> assets = new ArrayList<>();
        List<Skip> skips = new ArrayList<>();
        Walk walk = walkComponents(document);
        for (JsonNode component : walk.components()) {
            if (!isCryptographicAsset(component)) {
                continue;
            }
            try {
                // Named `extracted`, not anything beginning with "key". The exposure fence matches
                // identity[_-<space>]?key, so the type name followed by such a variable reads as the fenced token
                // across the space between them -- a rule about text, applied to text, with no idea what a type is.
                CryptoAssetIdentity.Identity extracted = identity.of(component, scope, refuted);
                List<JsonNode> occurrences = occurrencesOf(component);
                ExtractedAsset asset = new ExtractedAsset(extracted.key(), extracted.step(), extracted.asset(),
                        nameOf(component), extracted.redaction().storedPayload(),
                        OccurrenceEvidenceCapper.cap(occurrences == null ? null : retainedOccurrences(occurrences)),
                        occurrences == null ? 0 : occurrences.size(), extracted.guard(), extracted.findings());
                requireEncodable(asset);
                assets.add(asset);
            } catch (RuntimeException e) {
                // Deliberately broad, and deliberately not logged with the throwable. Producer input reaches every
                // derivation below this line; the failure classes are open-ended, and one of them must not be fatal.
                skips.add(new Skip(nameOf(component), e.getClass().getSimpleName()));
            }
        }
        return new Extraction(List.copyOf(assets), List.copyOf(skips), walk.depthLimitReached(), scopeUnavailable);
    }

    /** The component's occurrence objects in producer order, or {@code null} when it reported none. */
    private static List<JsonNode> occurrencesOf(JsonNode component) {
        JsonNode evidence = component.get("evidence");
        JsonNode occurrences = evidence == null ? null : evidence.get("occurrences");
        if (occurrences == null || !occurrences.isArray()) {
            return null;
        }
        List<JsonNode> objects = new ArrayList<>(occurrences.size());
        for (JsonNode occurrence : occurrences) {
            if (occurrence.isObject()) {
                objects.add(occurrence);
            }
        }
        return objects;
    }

    /**
     * The occurrences the cap can keep, converted for it, or {@code null} when the component reported none.
     *
     * <p>
     * Only the first {@link OccurrenceEvidenceCapper#MAX_OCCURRENCES} are converted: the cap keeps that prefix in
     * producer order and drops the rest whole, so converting a million occurrences to retain fifty was three copies of
     * the parsed subtree spent on a count the caller already has.
     *
     * <p>
     * <b>The location is not sanitized here.</b> A location is a real shape like
     * {@code tcp://user:pass@host:443/path?token=...}, and the keying path strips its credential or a password would be
     * hashed into the key; the stored evidence is the other half of the same rule, and the capper applies it to every
     * {@code location} member of every occurrence it retains, at every depth. A pass here sanitized the top-level
     * member a second time, which made the served string depend on neither pass alone -- deleting either left every
     * test green, and a paragraph calling this one load-bearing would have licensed weakening the other. The property
     * is pinned where it is observable, on the extracted evidence, not on which class produced it.
     *
     * <p>
     * A source that reported no evidence is distinct from one whose evidence capping emptied, and the capper preserves
     * that distinction downstream -- so the absent case is decided by the caller and never reaches here, and this
     * method always answers with a list.
     */
    private static List<Map<String, Object>> retainedOccurrences(List<JsonNode> occurrences) {
        List<JsonNode> retained = occurrences.size() > OccurrenceEvidenceCapper.MAX_OCCURRENCES
                ? occurrences.subList(0, OccurrenceEvidenceCapper.MAX_OCCURRENCES)
                : occurrences;
        List<Map<String, Object>> converted = new ArrayList<>(retained.size());
        for (JsonNode occurrence : retained) {
            converted.add(MAPPER.convertValue(occurrence, MAP_TYPE));
        }
        return converted;
    }

    /**
     * Refuses an asset whose stored surfaces carry a string with no UTF-8 encoding, so the refusal is a rule stated
     * here rather than an accident of which tier ran.
     *
     * <p>
     * {@link IdentityDigests#sha256Hex} refuses an unpaired surrogate in a pre-image, so a component spelling one into
     * a keyed slot was already a reported skip. A string that reaches storage without reaching a pre-image was not: a
     * cipher-suite name on a version-less protocol row, or an unread member of {@code algorithmProperties} on a row
     * keyed by family, was retained in a payload that has no valid encoding for the {@code jsonb} column -- so whether
     * the row survived was decided by the database, on a path that once rolled back a whole source upsert. Five
     * surfaces are what persistence receives, and each is checked: the component name, the stored payload, the
     * sanitized evidence, the provenance notes, and the findings -- which echo producer member names, so a surrogate in
     * a member the redaction dropped reached them on a tier whose pre-image never read that member.
     *
     * <p>
     * The one exemption is the occurrence {@code location}: {@link Occurrences} scrubs a surrogate there rather than
     * refusing it, and the evidence checked here is the scrubbed form. The exemption is that member alone -- a
     * surrogate in any sibling member of the same occurrence, name or value, still costs the component its row.
     */
    private static void requireEncodable(ExtractedAsset asset) {
        IdentityDigests.requireWellFormedUnicode(asset.componentName());
        requireEncodable(asset.retainedProperties());
        asset.normalized().notes().forEach(IdentityDigests::requireWellFormedUnicode);
        asset.findings().forEach(IdentityDigests::requireWellFormedUnicode);
        if (asset.evidence() != null) {
            asset.evidence().forEach(CbomAssetExtractor::requireEncodable);
        }
    }

    private static void requireEncodable(JsonNode node) {
        if (node == null) {
            return;
        }
        if (node.isTextual()) {
            IdentityDigests.requireWellFormedUnicode(node.textValue());
        } else if (node.isContainerNode()) {
            node.properties().forEach(member -> IdentityDigests.requireWellFormedUnicode(member.getKey()));
            node.forEach(CbomAssetExtractor::requireEncodable);
        }
    }

    private static void requireEncodable(Object value) {
        if (value instanceof String text) {
            IdentityDigests.requireWellFormedUnicode(text);
        } else if (value instanceof Map<?, ?> map) {
            map.forEach((key, member) -> {
                requireEncodable(key);
                requireEncodable(member);
            });
        } else if (value instanceof Iterable<?> members) {
            members.forEach(CbomAssetExtractor::requireEncodable);
        }
    }

    /**
     * A component this specification has an opinion about.
     *
     * <p>
     * Either declaration is enough. A component <em>typed</em> {@code cryptographic-asset} with no
     * {@code cryptoProperties} at all is not skipped -- it keys on the unroutable backstop tier with its name, and
     * there is one in the validation corpus. And a component carrying {@code cryptoProperties} while typed something
     * else is still a cryptographic asset by the only evidence that matters, since the type field is producer text like
     * any other.
     */
    private static boolean isCryptographicAsset(JsonNode component) {
        JsonNode type = component.get("type");
        boolean declaredType = type != null && type.isTextual() && "cryptographic-asset".equals(type.textValue());
        JsonNode properties = component.get("cryptoProperties");
        return declaredType || (properties != null && properties.isObject());
    }

    private static String nameOf(JsonNode component) {
        JsonNode name = component.get("name");
        return name != null && name.isTextual() ? name.textValue() : "";
    }

    private record Walk(List<JsonNode> components, boolean depthLimitReached) {
    }

    /**
     * Every component in the tree, in document order, without recursing.
     *
     * <p>
     * An explicit stack rather than a recursive descent: see {@link #MAX_DEPTH}. The children of a component are pushed
     * in reverse so they pop in document order, which keeps the output readable without making anything depend on it.
     */
    private static Walk walkComponents(JsonNode document) {
        List<JsonNode> found = new ArrayList<>();
        Deque<Entry> pending = new ArrayDeque<>();
        pushChildren(document.get("components"), 1, pending);
        boolean depthLimitReached = false;
        while (!pending.isEmpty()) {
            Entry entry = pending.pop();
            found.add(entry.component());
            if (entry.depth() >= MAX_DEPTH) {
                depthLimitReached = true;
                continue;
            }
            pushChildren(entry.component().get("components"), entry.depth() + 1, pending);
        }
        return new Walk(found, depthLimitReached);
    }

    private static void pushChildren(JsonNode components, int depth, Deque<Entry> pending) {
        if (components == null || !components.isArray()) {
            return;
        }
        for (int index = components.size() - 1; index >= 0; index--) {
            JsonNode child = components.get(index);
            if (child.isObject()) {
                pending.push(new Entry(child, depth));
            }
        }
    }

    private record Entry(JsonNode component, int depth) {
    }
}
