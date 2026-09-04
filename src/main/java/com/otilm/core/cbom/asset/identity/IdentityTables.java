package com.otilm.core.cbom.asset.identity;

import com.fasterxml.jackson.databind.JsonNode;
import com.otilm.core.serialization.ObjectMapperFactory;
import java.io.IOException;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.regex.Pattern;
import java.util.stream.Collectors;
import java.util.stream.Stream;

/**
 * The ratified identity and normalization decision tables. Data only, no behaviour.
 *
 * <p>
 * The tables are <em>data, never code</em>: they load from {@code cbom/identity-tables.json}, the same artifact the
 * reference implementation reads, so a vocabulary change is a reviewed data change rather than a code change in two
 * languages. The shipped file's SHA-256 is {@code a34c40d2f6fc...}. Every published cross-implementation agreement
 * figure predates it and was measured against {@code 1331969bb507...} -- quote an agreement number only with the
 * artifact hash it was taken against, because a number measured before a table change is a historical number, not a
 * current one.
 *
 * <p>
 * Every lookup here is fold-insensitive by way of {@link AsciiText#lookupKey}: a producer writing {@code aes} or
 * {@code md5} means the registry's {@code AES} and {@code MD5}, and keying the lowercase spelling verbatim split real
 * assets from every other producer's identical algorithm. What enters a key is always the <em>table's</em> spelling.
 */
public final class IdentityTables {

    private static final String RESOURCE = "cbom/identity-tables.json";

    private final Set<String> families;
    private final Map<String, Set<String>> pseudoFamilies;
    private final Map<String, String> curveCanonical;
    private final Map<String, String> curveAliases;
    /**
     * Curve spellings the registry does not list in bare form but producers write anyway. Read from the artifact rather
     * than held here: this set decides which digit runs the parameter-set parser is allowed to read, so an edit to it
     * re-keys -- and in code it re-keyed without moving the file that the byte-diff and the two pinned hashes watch, so
     * neither guard could see it.
     */
    private final List<String> extraCurveSpellings;
    private final Map<String, OidEntry> oidToFamily;
    private final Set<String> oidBlockedPrefixes;
    private final List<GrammarRule> nameGrammar;
    private final List<String> sizeStoplist;
    private final List<String> modeTokens;
    private final List<Pattern> cipherSuitePatterns;
    private final List<SecondaryMarker> secondaryMarkers;
    private final Pattern curveStrip;
    private final Pattern stoplistStrip;
    private final List<String> paddingTokens;
    private final Map<String, String> paddingAliases;
    private final Set<String> variantVocabulary;
    private final Map<String, String> variantSynonyms;
    private final Set<String> truncatableFamilies;
    private final Set<String> sentinels;

    private final Set<String> expressiblePrimitives;
    private final Map<String, String> primitiveDefaults;
    private final Map<String, String> familyTokens;
    private final Map<String, String> dnAttributeOids;
    private final Map<String, Integer> nameIntrinsicSizes;
    private final List<String> curveSpellingsByLength;
    private final List<CurveSpelling> curveSpellingPatterns;
    private final int sizeMin;
    private final int sizeMax;

    /** One row of the ordered name grammar: the family a spelling names, and the two guard forms it is matched with. */
    public record GrammarRule(Pattern strict, Pattern loose, Pattern unguarded, String family) {
    }

    /**
     * One curve spelling and the word-guarded pattern that finds it in a name.
     *
     * <p>
     * Precompiled here beside the other table-derived patterns. Compiled per call instead, this cost 254
     * {@code Pattern.compile} invocations for every EC-bearing name the pipeline normalized.
     */
    public record CurveSpelling(String spelling, Pattern word) {
    }

    /** A secondary construction token the name carries beside its family. */
    public record SecondaryMarker(String label, Pattern pattern) {
    }

    /**
     * What an OID arc says about an asset. Every field beyond the family is enrichment and may be absent.
     *
     * <p>
     * The strand's {@code primitive} column is deliberately not read: the arc never supplies the primitive, because a
     * correct arc contributing {@code block-cipher} where an OID-less producer had nothing made adding an OID change
     * the key. The column stays in the artifact as the arc's documentation and decides nothing here.
     */
    public record OidEntry(String family, Integer parameterSet, String mode, String curve, String matchedArc,
            List<String> residualArcs) {

        OidEntry matchedAt(String arc, List<String> residual) {
            return new OidEntry(family, parameterSet, mode, curve, arc, residual);
        }
    }

    private IdentityTables(JsonNode raw) {
        Node root = new Node(raw, "");
        List<String> familyList = textList(root.field("algorithmFamilies"));
        this.families = Set.copyOf(familyList);
        Node pseudo = root.field("pseudoFamilies");
        this.pseudoFamilies = pseudo
                .entries()
                .stream()
                .collect(Collectors.toUnmodifiableMap(Map.Entry::getKey, entry -> textSet(entry.getValue())));
        this.curveCanonical = textMap(root.field("curveCanonical"));
        this.curveAliases = curveAliases(root.field("curveAliases"));
        this.oidToFamily = oidEntries(root.field("oidToFamily"));
        this.extraCurveSpellings = textList(root.field("extraCurveSpellings"));
        this.oidBlockedPrefixes = textSet(root.field("oidBlockedPrefixes"));
        this.nameGrammar = grammar(root.field("nameGrammar"));
        this.sizeStoplist = textList(root.field("sizeStoplist"));
        this.modeTokens = textList(root.field("modeTokens"));
        this.cipherSuitePatterns = textList(root.field("cipherSuiteNamePatterns"))
                .stream()
                .map(pattern -> Pattern.compile(pattern, Pattern.CASE_INSENSITIVE))
                .toList();
        this.secondaryMarkers = markers(root.field("secondaryMarkers"));
        this.paddingTokens = textList(root.field("paddingTokens"));
        this.paddingAliases = textMap(root.field("paddingAliases"));
        this.variantVocabulary = textSet(root.field("variantVocabulary"));
        this.variantSynonyms = textMap(root.field("variantSynonyms"));
        this.truncatableFamilies = textSet(root.field("truncatableFamilies"));
        this.sentinels = textList(root.field("sentinels"))
                .stream()
                .map(AsciiText::fold)
                .collect(Collectors.toUnmodifiableSet());
        this.expressiblePrimitives = textList(root.field("primitivesExpressibleIn16"))
                .stream()
                .map(AsciiText::fold)
                .collect(Collectors.toUnmodifiableSet());
        this.primitiveDefaults = textMap(root.field("primitiveDefaults"));
        this.dnAttributeOids = textMap(root.field("dnShortNames"));
        Map<String, Integer> intrinsics = new LinkedHashMap<>();
        root
                .field("nameIntrinsicSizes")
                .entries()
                .forEach(entry -> intrinsics.put(AsciiText.fold(entry.getKey()), entry.getValue().integer()));
        // Insertion order is load-bearing, and Map.copyOf does not keep it. The intrinsic lookup is first-match-wins
        // over this map, and one name can carry two of its tokens: `X25519/X448` must take 256 from the x25519 it
        // mentions first, and `Ed25519/Ed448` likewise, rather than the 448 or 456 the second token would give. An
        // unordered map turned that into whichever bucket the hash happened to fill first.
        this.nameIntrinsicSizes = Collections.unmodifiableMap(intrinsics);
        Node sizeWhitelist = root.field("sizeWhitelist");
        this.sizeMin = sizeWhitelist.field("min").integer();
        this.sizeMax = sizeWhitelist.field("max").integer();

        this.familyTokens = familyTokens(pseudo.keys(), familyList);

        this.curveSpellingsByLength = curveSpellings();
        this.curveSpellingPatterns = curveSpellingsByLength
                .stream()
                // Below four characters a spelling is too short to be a word in a name without colliding.
                .filter(spelling -> spelling.length() >= 4)
                .map(spelling -> new CurveSpelling(spelling,
                        Pattern
                                .compile("(?<![A-Za-z0-9])" + Pattern.quote(spelling) + "(?![A-Za-z0-9])",
                                        Pattern.CASE_INSENSITIVE)))
                .toList();
        this.curveStrip = Pattern
                .compile("(?<![A-Za-z0-9])(?:" + alternation(curveStripTokens()) + ")(?![A-Za-z0-9])",
                        Pattern.CASE_INSENSITIVE);
        // Unguarded on the left on purpose: in `ChaCha20Poly1305` the Poly1305 token is preceded by a digit, so a
        // left-guarded strip leaves it in place and 1305 is then read as a key size. Stripping is not matching.
        this.stoplistStrip = Pattern
                .compile("(?:" + alternation(sizeStoplist) + ")(?![A-Za-z0-9])", Pattern.CASE_INSENSITIVE);
    }

    /**
     * Loads the ratified tables from the classpath. Fails loudly: a missing table is a broken build, not a runtime
     * state.
     */
    public static IdentityTables load() {
        try (InputStream stream = IdentityTables.class.getClassLoader().getResourceAsStream(RESOURCE)) {
            if (stream == null) {
                throw new IllegalStateException(
                        "The ratified identity tables are missing from the classpath: " + RESOURCE);
            }
            return of(ObjectMapperFactory.storage().readTree(stream));
        } catch (IOException e) {
            throw new IllegalStateException("The ratified identity tables could not be read: " + RESOURCE, e);
        }
    }

    /**
     * Reads tables from a parsed tree, refusing a malformed one.
     *
     * <p>
     * Package-private so the refusals in {@link Node} can be reached from a test. {@link #load} reads one fixed
     * classpath resource, so with only that entry point nothing could hand the loader a wrong-typed table -- and the
     * fail-open state this loader replaced, a mis-typed table read as empty with every vector green, was one regression
     * away from returning with the same green suite.
     */
    static IdentityTables of(JsonNode raw) {
        return new IdentityTables(raw);
    }

    /**
     * True when the value is one of the ratified "producer said nothing" spellings, which are treated as absent.
     *
     * <p>
     * {@link AsciiText#strip}, not {@code String.strip}. The JDK consults {@code Character.isWhitespace}, which does
     * not treat U+0085, U+00A0, U+2007 or U+202F as whitespace, so {@code "0.0.0.0\u00A0"} pasted out of a document
     * escaped the sentinel guard and grew a permanent bogus version bucket beside the real one. The specification's
     * whitespace set is the one this class already uses for every lookup key, and the disagreement between the two is
     * one-directional -- the reference set is strictly wider -- so substituting it can only widen what is recognised.
     */
    public boolean isSentinel(String value) {
        return value != null && sentinels.contains(AsciiText.fold(AsciiText.strip(value)));
    }

    /** True when {@code pseudo} is a pseudo-family that {@code concrete} belongs to. */
    public boolean subsumes(String pseudo, String concrete) {
        return pseudo != null && concrete != null && pseudoFamilies.getOrDefault(pseudo, Set.of()).contains(concrete);
    }

    /**
     * The legal family token a producer's declaration names, or {@code null}.
     *
     * <p>
     * A value outside the vocabulary contributes nothing to the key and derivation proceeds by name, so the asset lands
     * where its siblings are. Measured: 11 corpus assets declare values outside the vocabulary and 9 same-name groups
     * split because the declaration used to be taken verbatim.
     */
    public String familyToken(String declared) {
        // No strip, deliberately. AsciiText.lookupKey already deletes the reference whitespace set wherever it sits --
        // U+00A0 among its separators -- so a declared family carrying one has always resolved. core#2165 item 18
        // listed this site beside isSentinel; it stopped being a defect when core#2173 gave LOOKUP_SEPARATORS the
        // reference set, and a strip here would be a change that changes nothing.
        return declared == null ? null : familyTokens.get(AsciiText.lookupKey(declared));
    }

    public Set<String> families() {
        return families;
    }

    public Map<String, Set<String>> pseudoFamilies() {
        return pseudoFamilies;
    }

    public Map<String, String> curveCanonical() {
        return curveCanonical;
    }

    public Map<String, String> curveAliases() {
        return curveAliases;
    }

    public Map<String, OidEntry> oidToFamily() {
        return oidToFamily;
    }

    public Set<String> oidBlockedPrefixes() {
        return oidBlockedPrefixes;
    }

    public List<GrammarRule> nameGrammar() {
        return nameGrammar;
    }

    public List<String> sizeStoplist() {
        return sizeStoplist;
    }

    public List<String> modeTokens() {
        return modeTokens;
    }

    /**
     * Whether a declared primitive is one CycloneDX 1.6 can express, folded for comparison.
     *
     * <p>
     * The table has shipped this vocabulary since the first cut and nothing read it, so a producer's declared primitive
     * was the one typed slot that reached the key as raw text. A 1.7-only value such as {@code key-wrap} therefore
     * keyed on its spelling, and the same asset rendered under 1.6 -- which cannot say it -- keyed differently. That is
     * the split every other slot is bounded to prevent.
     */
    public boolean isExpressiblePrimitive(String value) {
        return value != null && expressiblePrimitives.contains(AsciiText.fold(value));
    }

    public List<Pattern> cipherSuitePatterns() {
        return cipherSuitePatterns;
    }

    public List<SecondaryMarker> secondaryMarkers() {
        return secondaryMarkers;
    }

    public List<CurveSpelling> curveSpellingPatterns() {
        return curveSpellingPatterns;
    }

    public Pattern curveStrip() {
        return curveStrip;
    }

    public Pattern stoplistStrip() {
        return stoplistStrip;
    }

    public List<String> curveSpellingsByLength() {
        return curveSpellingsByLength;
    }

    public List<String> paddingTokens() {
        return paddingTokens;
    }

    public Map<String, String> paddingAliases() {
        return paddingAliases;
    }

    public Set<String> variantVocabulary() {
        return variantVocabulary;
    }

    public Map<String, String> variantSynonyms() {
        return variantSynonyms;
    }

    public Set<String> truncatableFamilies() {
        return truncatableFamilies;
    }

    public Map<String, String> primitiveDefaults() {
        return primitiveDefaults;
    }

    /**
     * Distinguished-name attribute types, short and long spellings alike, mapped to dotted OIDs.
     *
     * <p>
     * Read from the table rather than hardcoded, and that is not a style preference. Both implementations once carried
     * their own abbreviation-only copy, so a producer writing {@code commonName=} got a lower-cased short name in the
     * slot where the specification says a dotted OID always goes -- and because both sides reproduced the wart
     * together, no cross-implementation agreement measurement could ever have found it.
     */
    public Map<String, String> dnAttributeOids() {
        return dnAttributeOids;
    }

    public Map<String, Integer> nameIntrinsicSizes() {
        return nameIntrinsicSizes;
    }

    public int sizeMin() {
        return sizeMin;
    }

    public int sizeMax() {
        return sizeMax;
    }

    /**
     * The fold-insensitive lookup from a declared family spelling to the table's own, built in table order.
     *
     * <p>
     * Built from the artifact's ordered arrays, not from the {@code Set} copies. {@code Set.copyOf} iterates in an
     * order that differs from one JVM to the next, so with a later-wins {@code put} two tokens folding to one lookup
     * key would have resolved differently across restarts -- deterministic today only because no two tokens fold
     * together. Order alone would make such a pair stable, not right: a declaration naming two table spellings has no
     * single "table's spelling" to enter the key with, so the pair is refused and the table fails to load.
     */
    private static Map<String, String> familyTokens(List<String> pseudoTokens, List<String> familyTokens) {
        Map<String, String> tokens = new LinkedHashMap<>();
        Stream.concat(pseudoTokens.stream(), familyTokens.stream()).forEach(token -> {
            String key = AsciiText.lookupKey(token);
            String previous = tokens.putIfAbsent(key, token);
            if (previous != null && !previous.equals(token)) {
                throw new IllegalStateException(RESOURCE + ": family tokens `" + previous + "` and `" + token
                        + "` fold to the same lookup key `" + key + "`");
            }
        });
        return Map.copyOf(tokens);
    }

    /**
     * The fold-insensitive alias lookup, refusing two spellings that fold onto one key with different targets.
     *
     * <p>
     * The ruling {@link #familyTokens} follows, applied to the second folded table: a later-wins {@code put} let one
     * alias edit re-target a curve with the loader silent, while the generator had already learnt to refuse the same
     * pair -- the two ends of the artifact now agree. Two spellings of ONE target that fold together
     * ({@code nist/P-256} and {@code nistp256}) are not a collision: the lookup has a single answer either way, and the
     * shipped table carries nine such pairs.
     */
    private static Map<String, String> curveAliases(Node node) {
        Map<String, String> aliases = new HashMap<>();
        Map<String, String> spellings = new HashMap<>();
        for (Map.Entry<String, Node> entry : node.entries()) {
            String key = AsciiText.lookupKey(entry.getKey());
            String target = entry.getValue().text();
            String previous = aliases.putIfAbsent(key, target);
            if (previous == null) {
                spellings.put(key, entry.getKey());
            } else if (!previous.equals(target)) {
                throw new IllegalStateException(RESOURCE + ": curve aliases `" + spellings.get(key) + "` -> `"
                        + previous + "` and `" + entry.getKey() + "` -> `" + target + "` fold to the same lookup key `"
                        + key + "` with different targets");
            }
        }
        return Map.copyOf(aliases);
    }

    private List<String> curveStripTokens() {
        Set<String> tokens = new HashSet<>(extraCurveSpellings);
        curveCanonical.keySet().forEach(token -> tokens.add(token.substring(token.indexOf('/') + 1)));
        return longestFirst(tokens);
    }

    private List<String> curveSpellings() {
        Set<String> spellings = new LinkedHashSet<>();
        curveCanonical.keySet().stream().filter(token -> !token.contains("/")).forEach(spellings::add);
        curveCanonical.keySet().forEach(token -> spellings.add(token.substring(token.indexOf('/') + 1)));
        spellings.addAll(extraCurveSpellings);
        return longestFirst(spellings);
    }

    /** Longest first, so `P-256` is removed before any bare `256` can be read out of it. */
    private static List<String> longestFirst(Set<String> tokens) {
        List<String> ordered = new ArrayList<>(tokens);
        ordered.sort(Comparator.comparingInt(String::length).reversed().thenComparing(Comparator.naturalOrder()));
        return List.copyOf(ordered);
    }

    /**
     * One alternation rather than a substitution per token: the per-token loops drove millions of calls over a corpus.
     */
    private static String alternation(List<String> tokens) {
        return tokens.stream().map(Pattern::quote).collect(Collectors.joining("|"));
    }

    /** The trailing negative-lookahead a grammar spelling ends with, stripped to read the halves out of a hybrid. */
    private static final Pattern TRAILING_GUARD = Pattern.compile("\\(\\?![^)]*\\)$");

    private static List<GrammarRule> grammar(Node node) {
        List<GrammarRule> rules = new ArrayList<>();
        for (Node rule : node.elements()) {
            String pattern = rule.field("pattern").text();
            // The loose form drops the LEFT word guard. The guard is right for deciding the winning family -- it stops
            // `design` matching DES -- but wrong for asking "does this name also mention a digest", because the real
            // spellings run the words together: `HMACMD5` merged with bare `HMAC` for exactly this reason.
            String loose = pattern.replace("(?<![A-Za-z0-9])", "");
            // The unguarded form drops the TRAILING guard too, used only to read the halves out of a hybrid name,
            // where producers glue tokens together with no separator at all and a right-hand guard hides `X25519`.
            String unguarded = TRAILING_GUARD.matcher(loose).replaceAll("");
            rules
                    .add(new GrammarRule(Pattern.compile(pattern, Pattern.CASE_INSENSITIVE),
                            Pattern.compile(loose, Pattern.CASE_INSENSITIVE),
                            Pattern.compile(unguarded, Pattern.CASE_INSENSITIVE), rule.field("family").text()));
        }
        return List.copyOf(rules);
    }

    private static List<SecondaryMarker> markers(Node node) {
        List<SecondaryMarker> markers = new ArrayList<>();
        for (Node marker : node.elements()) {
            List<Node> pair = marker.elements(2);
            markers
                    .add(new SecondaryMarker(pair.get(0).text(),
                            Pattern.compile(pair.get(1).text(), Pattern.CASE_INSENSITIVE)));
        }
        return List.copyOf(markers);
    }

    private static Map<String, OidEntry> oidEntries(Node node) {
        Map<String, OidEntry> entries = new HashMap<>();
        for (Map.Entry<String, Node> entry : node.entries()) {
            Node value = entry.getValue();
            entries
                    .put(entry.getKey(),
                            new OidEntry(value.optionalText("family"), value.optionalInteger("parameterSet"),
                                    value.optionalText("mode"), value.optionalText("curve"), null, List.of()));
        }
        return Map.copyOf(entries);
    }

    private static Set<String> textSet(Node node) {
        return Set.copyOf(textList(node));
    }

    private static List<String> textList(Node node) {
        return node.elements().stream().map(Node::text).toList();
    }

    private static Map<String, String> textMap(Node node) {
        Map<String, String> values = new LinkedHashMap<>();
        node.entries().forEach(entry -> values.put(entry.getKey(), entry.getValue().text()));
        return Collections.unmodifiableMap(values);
    }

    /**
     * One node of the artifact and the path that reached it, so a refusal names the table and the shape it wanted.
     *
     * <p>
     * Jackson's own traversal is fail-open: {@code forEach} over a scalar visits nothing, {@code properties()} of an
     * array is empty, and {@code asInt()} of text is 0. Read that way, a mis-typed table loaded as an <em>empty</em>
     * one -- replacing {@code oidBlockedPrefixes} with a string left all 537 vector executions green and only the
     * artifact hash red -- and a missing key surfaced as a bare {@code NullPointerException}. Every read goes through
     * here instead, so a malformed artifact is a startup failure that says which table is wrong and how.
     */
    private record Node(JsonNode json, String path) {

        Node field(String key) {
            JsonNode child = object().get(key);
            String childPath = at(key);
            if (child == null || child.isNull()) {
                throw new IllegalStateException(RESOURCE + ": table `" + childPath + "` is missing");
            }
            return new Node(child, childPath);
        }

        /** The keys of an object, in the artifact's order. */
        List<String> keys() {
            return object().properties().stream().map(Map.Entry::getKey).toList();
        }

        List<Map.Entry<String, Node>> entries() {
            return object()
                    .properties()
                    .stream()
                    .map(entry -> Map.entry(entry.getKey(), new Node(entry.getValue(), at(entry.getKey()))))
                    .toList();
        }

        List<Node> elements() {
            JsonNode array = array();
            List<Node> elements = new ArrayList<>(array.size());
            for (int index = 0; index < array.size(); index++) {
                elements.add(new Node(array.get(index), path + "[" + index + "]"));
            }
            return elements;
        }

        /**
         * The elements of an array that must hold exactly {@code size} of them. A short tuple failed already; a long
         * one loaded with its tail ignored, and a marker written as {@code [label, pattern, pattern]} is a typo the
         * table cannot mean.
         */
        List<Node> elements(int size) {
            List<Node> elements = elements();
            if (elements.size() != size) {
                throw new IllegalStateException(RESOURCE + ": table `" + path + "` must hold exactly " + size
                        + " elements, not " + elements.size());
            }
            return elements;
        }

        String text() {
            if (!json.isTextual()) {
                throw shape("a string");
            }
            return json.textValue();
        }

        int integer() {
            if (!json.isIntegralNumber() || !json.canConvertToInt()) {
                throw shape("an integer");
            }
            return json.intValue();
        }

        String optionalText(String key) {
            JsonNode child = object().get(key);
            return child == null || child.isNull() ? null : new Node(child, at(key)).text();
        }

        Integer optionalInteger(String key) {
            JsonNode child = object().get(key);
            return child == null || child.isNull() ? null : new Node(child, at(key)).integer();
        }

        private JsonNode object() {
            if (!json.isObject()) {
                throw shape("an object");
            }
            return json;
        }

        private JsonNode array() {
            if (!json.isArray()) {
                throw shape("an array");
            }
            return json;
        }

        private String at(String key) {
            return path.isEmpty() ? key : path + "." + key;
        }

        private IllegalStateException shape(String expected) {
            return new IllegalStateException(
                    RESOURCE + ": table `" + path + "` must be " + expected + ", not " + json.getNodeType());
        }
    }
}
