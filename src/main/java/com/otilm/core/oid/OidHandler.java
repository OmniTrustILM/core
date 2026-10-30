package com.otilm.core.oid;

import com.otilm.api.model.common.validation.OidFormat;
import com.otilm.api.model.core.oid.OidCategory;
import java.time.Duration;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import java.util.Set;
import java.util.TreeMap;
import java.util.TreeSet;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicReference;
import java.util.regex.Pattern;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class OidHandler {

    private static final Logger logger = LoggerFactory.getLogger(OidHandler.class);

    private OidHandler() {
    }

    /** Dotted-decimal OID form (e.g. {@code 2.5.4.3}); anything else is treated as a short RDN code. */
    // Shared with the contract's @Pattern validation so both agree, and because the arc rules are easy to get
    // subtly wrong: a first arc of 0 or 1 caps the second at 39, which a plain [0-2](\.\d+)+ misses.
    private static final Pattern OID_PATTERN = Pattern.compile(OidFormat.REGEX);

    /** {@code true} if {@code value} is a well-formed dotted-decimal OID (never {@code null}-safe true). */
    public static boolean isOid(String value) {
        return value != null && OID_PATTERN.matcher(value).matches();
    }

    private static final Map<OidCategory, Map<String, OidRecord>> oidCache = new ConcurrentHashMap<>();

    /**
     * Case-insensitive RDN code/altCode → OID lookup. Rebuilt on every RDN cache mutation and republished as an
     * immutable snapshot, so readers on hot paths (DN parsing) never iterate a map another thread may be mutating.
     */
    private static final AtomicReference<Map<String, String>> rdnCodeToOid = new AtomicReference<>(
            Collections.emptyMap());

    /**
     * Bumped under {@link #WRITE_LOCK} by every publication. Lets a caller that read source data without holding the
     * lock detect that the registry moved underneath it and abandon its now-stale snapshot, instead of holding the lock
     * across those reads.
     */
    private static long generation;

    /** Keeps a lasting conflict visible in recent log output without repeating it on every rebuild. */
    private static final PersistentWarningThrottle conflictWarnings = new PersistentWarningThrottle(
            Duration.ofHours(1));

    /** Code tokens claimed by more than one OID, republished on every rebuild. See {@link #getRdnCodeConflicts}. */
    private static final AtomicReference<Map<String, Set<String>>> rdnCodeConflicts = new AtomicReference<>(Map.of());

    /**
     * Serializes writers so that the read-copy-publish of a per-category map and the rebuild of the derived
     * {@link #rdnCodeToOid} index happen as one unit. A private monitor is used rather than the
     * {@code OidHandler.class} object so foreign code cannot contend on the same lock.
     */
    private static final Object WRITE_LOCK = new Object();

    /** Registry version, for the optimistic publish in {@link #cacheAllCategories}. */
    public static long getGeneration() {
        synchronized (WRITE_LOCK) {
            return generation;
        }
    }

    /**
     * Replaces every supplied category and rebuilds the derived RDN index once, or publishes nothing if the registry
     * moved since {@code expectedGeneration} was read.
     *
     * <p>
     * The guard is what lets a full refresh read its source data without holding {@link #WRITE_LOCK}: a concurrent
     * single-entry publication bumps the generation, so the refresh abandons a snapshot that would otherwise clobber a
     * committed mutation. Categories absent from {@code byCategory} are left untouched — {@code null} means "not
     * loaded" to every reader, so clearing them would break callers that dereference {@link #getOidCache} directly.
     *
     * @return {@code true} when published, {@code false} when abandoned as stale
     */
    public static boolean cacheAllCategories(long expectedGeneration,
            Map<OidCategory, Map<String, OidRecord>> byCategory) {
        synchronized (WRITE_LOCK) {
            if (generation != expectedGeneration) {
                return false;
            }
            byCategory
                    .forEach((category, records) -> oidCache
                            .put(category, Collections.unmodifiableMap(new HashMap<>(records))));
            generation++;
            if (byCategory.containsKey(OidCategory.RDN_ATTRIBUTE_TYPE)) {
                refreshRdnCodeLookup(OidCategory.RDN_ATTRIBUTE_TYPE);
            }
            return true;
        }
    }

    /**
     * The published per-category map, or {@code null} when the category is not loaded. Immutable — see
     * {@link #cacheOidCategory}.
     */
    public static Map<String, OidRecord> getOidCache(OidCategory oidCategory) {
        return oidCache.get(oidCategory);
    }

    public static void cacheOidCategory(OidCategory category, Map<String, OidRecord> oidRecordMap) {
        synchronized (WRITE_LOCK) {
            // Publish an immutable defensive copy: per-category maps are iterated lock-free by
            // readers (getCodeToOidMap, style snapshots), so a caller mutating the passed map
            // after publish would desync oidCache from the derived rdnCodeToOid index. Copying
            // here makes the copy-on-write contract structural rather than convention-only.
            oidCache.put(category, Collections.unmodifiableMap(new HashMap<>(oidRecordMap)));
            generation++;
            refreshRdnCodeLookup(category);
        }
    }

    public static void cacheOid(OidCategory category, String oid, OidRecord oidRecord) {
        synchronized (WRITE_LOCK) {
            // Copy-on-write: build the next map fresh, then publish it immutable so readers never
            // observe a map another thread might mutate. getOrDefault keeps the first write to an
            // as-yet-uncached category from throwing.
            Map<String, OidRecord> next = new HashMap<>(oidCache.getOrDefault(category, Map.of()));
            next.put(oid, oidRecord);
            oidCache.put(category, Collections.unmodifiableMap(next));
            generation++;
            refreshRdnCodeLookup(category);
        }
    }

    /** OID for an RDN code or alternative code, matched case-insensitively; {@code null} when unknown. */
    public static String getOidForRdnCode(String code) {
        return code == null ? null : rdnCodeToOid.get().get(code);
    }

    /**
     * The published, immutable, case-insensitive RDN code/altCode → OID snapshot. Capture it once and reuse it for a
     * whole DN so every RDN of one subject resolves against the same registry state, rather than re-reading the
     * reference per attribute.
     */
    public static Map<String, String> getRdnCodeToOidMap() {
        return rdnCodeToOid.get();
    }

    private static void refreshRdnCodeLookup(OidCategory category) {
        if (category != OidCategory.RDN_ATTRIBUTE_TYPE) {
            return;
        }
        // The single writer of conflict state: this runs under WRITE_LOCK, so the published snapshot and
        // the index it describes always come from the same rebuild. Readers never publish.
        Map<String, Set<String>> conflicts = new TreeMap<>(String.CASE_INSENSITIVE_ORDER);
        Map<String, String> lookup = buildCodeToOid(conflicts);
        rdnCodeToOid.set(Collections.unmodifiableMap(lookup));
        publishRdnCodeConflicts(conflicts, lookup);
    }

    /**
     * RDN code/altCode → OID, matched case-insensitively so the authoring-time gate and request-time resolution agree.
     * Codes and alt codes share one flat namespace, so two OIDs can claim the same token; see {@link #claimToken} for
     * how that is resolved.
     */
    public static Map<String, String> getCodeToOidMap() {
        return buildCodeToOid(new TreeMap<>(String.CASE_INSENSITIVE_ORDER));
    }

    /**
     * Builds the code → OID index, recording any contested token into {@code conflicts}. Side-effect free: publication
     * is the caller's job, so request-path readers cannot race the writer.
     */
    private static Map<String, String> buildCodeToOid(Map<String, Set<String>> conflicts) {
        Map<String, String> reverseMap = new TreeMap<>(String.CASE_INSENSITIVE_ORDER);
        Set<String> systemClaimants = new TreeSet<>(String.CASE_INSENSITIVE_ORDER);
        Map<String, OidRecord> rdnCache = oidCache.get(OidCategory.RDN_ATTRIBUTE_TYPE);
        if (rdnCache == null) {
            return reverseMap;
        }
        // Sorted so a contested token resolves the same way on every rebuild, rather than by the
        // iteration order of the backing HashMap.
        for (String oid : new TreeSet<>(rdnCache.keySet())) {
            OidRecord oidRecord = rdnCache.get(oid);
            if (oidRecord.code() != null) {
                claimToken(reverseMap, systemClaimants, conflicts, oidRecord.code(), oid, oidRecord.system());
            }
            if (oidRecord.altCodes() != null) {
                for (String altCode : oidRecord.altCodes()) {
                    if (altCode != null) {
                        claimToken(reverseMap, systemClaimants, conflicts, altCode, oid, oidRecord.system());
                    }
                }
            }
        }
        return reverseMap;
    }

    /**
     * RDN code tokens claimed by more than one OID, mapped to every claimant. Empty when the registry is unambiguous.
     */
    public static Map<String, Set<String>> getRdnCodeConflicts() {
        return rdnCodeConflicts.get();
    }

    /**
     * Publishes the current conflict set, warning when it changes and periodically while it persists. The registry
     * rebuilds on {@code settings.cache.refresh-interval} (30 s by default), so warning per rebuild would repeat
     * thousands of times a day, while warning only on change would make silence mean both "resolved" and "still broken,
     * already reported".
     */
    private static void publishRdnCodeConflicts(Map<String, Set<String>> conflicts, Map<String, String> resolved) {
        // Deep-immutable, and case-insensitive like every other code lookup here. Both matter because
        // this is process-wide static state handed out through a public accessor: a mutable claimant set
        // would let a caller corrupt it, and TreeMap(Map) would drop the comparator.
        Map<String, Set<String>> snapshot = new TreeMap<>(String.CASE_INSENSITIVE_ORDER);
        conflicts
                .forEach((token, claimants) -> snapshot
                        .put(token, Collections.unmodifiableSortedSet(new TreeSet<>(claimants))));
        Map<String, Set<String>> published = Collections.unmodifiableMap(snapshot);
        Map<String, Set<String>> previous = rdnCodeConflicts.getAndSet(published);
        if (!conflictWarnings.shouldWarn(!published.equals(previous), !published.isEmpty())) {
            return;
        }
        published
                .forEach((token, claimants) -> logger
                        .warn("RDN code '{}' is claimed by OIDs {}; resolving it to {}. Rename the custom OID entry's code "
                                + "or alt code to remove the ambiguity.", token, claimants, resolved.get(token)));
    }

    /**
     * Assigns one code token to an OID, resolving a contest in favour of the operator-registered entry. A custom OID
     * entry was already resolving that token before its OID became a system OID, so an upgrade must not silently
     * repoint it; the built-in entry stays reachable by its dotted OID. Contests between two entries of the same kind
     * keep the lexicographically first OID; determinism is the guarantee, not any numeric ordering of the arcs.
     */
    private static void claimToken(Map<String, String> reverseMap, Set<String> systemClaimants,
            Map<String, Set<String>> conflicts, String token, String oid, boolean candidateIsSystem) {
        String incumbent = reverseMap.get(token);
        if (incumbent == null || incumbent.equals(oid)) {
            reverseMap.put(token, oid);
            if (candidateIsSystem) {
                systemClaimants.add(token);
            } else {
                systemClaimants.remove(token);
            }
            return;
        }
        // Decided on record provenance, not on whether the dotted OID happens to be built-in: a custom
        // row can occupy a system OID (see getOidToRecordMap's putIfAbsent), and asking SystemOid.fromOID
        // would misclassify that operator record as built-in and make it lose its own token.
        boolean incumbentIsSystem = systemClaimants.contains(token);
        boolean candidateWins = incumbentIsSystem && !candidateIsSystem;
        reverseMap.put(token, candidateWins ? oid : incumbent);
        if (candidateWins) {
            systemClaimants.remove(token);
        }
        conflicts.computeIfAbsent(token, t -> new TreeSet<>()).addAll(Set.of(incumbent, oid));
    }

    public static void removeCachedOid(OidCategory category, String oid) {
        synchronized (WRITE_LOCK) {
            Map<String, OidRecord> current = oidCache.get(category);
            // Removing from a never-loaded category is a no-op: don't materialize an empty entry,
            // so getOidCache(category) stays null for callers that read null as "not loaded yet".
            if (current == null) {
                return;
            }
            Map<String, OidRecord> next = new HashMap<>(current);
            next.remove(oid);
            oidCache.put(category, Collections.unmodifiableMap(next));
            generation++;
            refreshRdnCodeLookup(category);
        }
    }
}
