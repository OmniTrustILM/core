package com.otilm.core.oid;

import com.otilm.api.model.core.oid.OidCategory;

import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import java.util.TreeMap;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicReference;
import java.util.regex.Pattern;

public class OidHandler {

    private OidHandler() {
    }

    /** Dotted-decimal OID form (e.g. {@code 2.5.4.3}); anything else is treated as a short RDN code. */
    private static final Pattern OID_PATTERN = Pattern.compile("^[0-2](\\.(0|[1-9]\\d{0,38})){1,127}$");

    /** {@code true} if {@code value} is a well-formed dotted-decimal OID (never {@code null}-safe true). */
    public static boolean isOid(String value) {
        return value != null && OID_PATTERN.matcher(value).matches();
    }

    private static final Map<OidCategory, Map<String, OidRecord>> oidCache = new ConcurrentHashMap<>();

    /**
     * Case-insensitive RDN code/altCode → OID lookup. Rebuilt on every RDN cache mutation and
     * republished as an immutable snapshot, so readers on hot paths (DN parsing) never iterate
     * a map another thread may be mutating.
     */
    private static final AtomicReference<Map<String, String>> rdnCodeToOid =
            new AtomicReference<>(Collections.emptyMap());

    /**
     * Serializes writers so that the read-copy-publish of a per-category map and the rebuild of the
     * derived {@link #rdnCodeToOid} index happen as one unit. A private monitor is used rather than
     * the {@code OidHandler.class} object so foreign code cannot contend on the same lock.
     */
    private static final Object WRITE_LOCK = new Object();

    public static Map<String, OidRecord> getOidCache(OidCategory oidCategory) {
        return oidCache.get(oidCategory);
    }

    public static void cacheOidCategory(OidCategory category, Map<String, OidRecord> oidRecordMap) {
        synchronized (WRITE_LOCK) {
            oidCache.put(category, oidRecordMap);
            refreshRdnCodeLookup(category);
        }
    }

    public static void cacheOid(OidCategory category, String oid, OidRecord oidRecord) {
        synchronized (WRITE_LOCK) {
            // Copy-on-write: published per-category maps are iterated lock-free by readers
            // (getCodeToOidMap, style snapshots), so never mutate one in place. getOrDefault
            // keeps the first write to an as-yet-uncached category from throwing.
            Map<String, OidRecord> next = new HashMap<>(oidCache.getOrDefault(category, Map.of()));
            next.put(oid, oidRecord);
            oidCache.put(category, next);
            refreshRdnCodeLookup(category);
        }
    }

    /** OID for an RDN code or alternative code, matched case-insensitively; {@code null} when unknown. */
    public static String getOidForRdnCode(String code) {
        return code == null ? null : rdnCodeToOid.get().get(code);
    }

    /**
     * The published, immutable, case-insensitive RDN code/altCode → OID snapshot. Capture it once
     * and reuse it for a whole DN so every RDN of one subject resolves against the same registry
     * state, rather than re-reading the reference per attribute.
     */
    public static Map<String, String> getRdnCodeToOidMap() {
        return rdnCodeToOid.get();
    }

    private static void refreshRdnCodeLookup(OidCategory category) {
        if (category != OidCategory.RDN_ATTRIBUTE_TYPE) {
            return;
        }
        Map<String, String> lookup = new TreeMap<>(String.CASE_INSENSITIVE_ORDER);
        lookup.putAll(getCodeToOidMap());
        rdnCodeToOid.set(Collections.unmodifiableMap(lookup));
    }

    public static Map<String, String> getCodeToOidMap() {
        Map<String, String> reverseMap = new HashMap<>();
        Map<String, OidRecord> rdnCache = oidCache.get(OidCategory.RDN_ATTRIBUTE_TYPE);
        if (rdnCache == null) {
            return reverseMap;
        }
        for (Map.Entry<String, OidRecord> entry : rdnCache.entrySet()) {
            String oidKey = entry.getKey();
            OidRecord oidRecord = entry.getValue();

            // map the code to the oidKey
            if (oidRecord.code() != null) {
                reverseMap.put(oidRecord.code(), oidKey);
            }

            // map all altCodes to the oidKey
            if (oidRecord.altCodes() != null) {
                for (String altCode : oidRecord.altCodes()) {
                    if (altCode != null) {
                        reverseMap.put(altCode, oidKey);
                    }
                }
            }
        }
        return reverseMap;
    }


    public static void removeCachedOid(OidCategory category, String oid) {
        synchronized (WRITE_LOCK) {
            Map<String, OidRecord> next = new HashMap<>(oidCache.getOrDefault(category, Map.of()));
            next.remove(oid);
            oidCache.put(category, next);
            refreshRdnCodeLookup(category);
        }
    }
}
