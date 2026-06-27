package com.otilm.core.oid;

import com.otilm.api.model.core.oid.OidCategory;

import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

public class OidHandler {

    private OidHandler() {
    }

    private static final Map<OidCategory, Map<String, OidRecord>> oidCache = new ConcurrentHashMap<>();

    public static Map<String, OidRecord> getOidCache(OidCategory oidCategory) {
        return oidCache.get(oidCategory);
    }

    public static void cacheOidCategory(OidCategory category, Map<String, OidRecord> oidRecordMap) {
        oidCache.put(category, oidRecordMap);
    }

    public static void cacheOid(OidCategory category, String oid, OidRecord oidRecord) {
        oidCache.get(category).put(oid, oidRecord);
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
        oidCache.get(category).remove(oid);
    }
}
