package com.otilm.core.oid;

import com.otilm.api.model.core.oid.OidCategory;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.lang.reflect.Field;
import java.util.EnumMap;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;

/**
 * Pure unit coverage for the {@link OidHandler} RDN-code lookup and copy-on-write mutators —
 * no Spring context.
 *
 * <p>The OID cache is process-wide static state shared across the surefire JVM, so this class
 * snapshots every category it touches in {@code @BeforeAll} and restores it in {@code @AfterAll}
 * (mirroring {@code X509RequestContentRendererTest.ToX500Principal}) rather than leaking state
 * into other test classes.
 */
class OidHandlerTest {

    private static final OidCategory[] TOUCHED =
            {OidCategory.RDN_ATTRIBUTE_TYPE, OidCategory.GENERIC, OidCategory.EXTENDED_KEY_USAGE};

    private static final Map<OidCategory, Map<String, OidRecord>> saved = new EnumMap<>(OidCategory.class);

    @BeforeAll
    static void snapshotTouchedCategories() {
        for (OidCategory category : TOUCHED) {
            Map<String, OidRecord> existing = OidHandler.getOidCache(category);
            saved.put(category, existing == null ? null : new HashMap<>(existing));
        }
    }

    @AfterAll
    static void restoreTouchedCategories() {
        for (OidCategory category : TOUCHED) {
            Map<String, OidRecord> original = saved.get(category);
            if (original == null) {
                evictCategory(category);
            } else {
                OidHandler.cacheOidCategory(category, original);
            }
        }
    }

    @BeforeEach
    void resetRdnCache() {
        OidHandler.cacheOidCategory(OidCategory.RDN_ATTRIBUTE_TYPE, new HashMap<>());
    }

    @Test
    void getOidForRdnCode_returnsNullForNullInput() {
        assertThat(OidHandler.getOidForRdnCode(null)).isNull();
    }

    @Test
    void getOidForRdnCode_returnsNullForUnknownCode() {
        assertThat(OidHandler.getOidForRdnCode("NOPE")).isNull();
    }

    @Test
    void getOidForRdnCode_matchesCodeAndAltCodesCaseInsensitively() {
        OidHandler.cacheOid(OidCategory.RDN_ATTRIBUTE_TYPE, "1.2.840.113549.1.9.1",
                OidRecord.builder().displayName("Email").code("EMAIL")
                        .altCodes(List.of("E", "EMAILADDRESS")).build());

        assertThat(OidHandler.getOidForRdnCode("EMAIL")).isEqualTo("1.2.840.113549.1.9.1");
        assertThat(OidHandler.getOidForRdnCode("email")).isEqualTo("1.2.840.113549.1.9.1");
        assertThat(OidHandler.getOidForRdnCode("e")).isEqualTo("1.2.840.113549.1.9.1");
        assertThat(OidHandler.getOidForRdnCode("EmailAddress")).isEqualTo("1.2.840.113549.1.9.1");
    }

    @Test
    void removeCachedOid_deregistersRdnCode() {
        OidHandler.cacheOid(OidCategory.RDN_ATTRIBUTE_TYPE, "2.5.4.3",
                OidRecord.builder().displayName("Common Name").code("CN").build());
        assertThat(OidHandler.getOidForRdnCode("cn")).isEqualTo("2.5.4.3");

        OidHandler.removeCachedOid(OidCategory.RDN_ATTRIBUTE_TYPE, "2.5.4.3");

        assertThat(OidHandler.getOidForRdnCode("cn")).isNull();
        assertThat(OidHandler.getOidCache(OidCategory.RDN_ATTRIBUTE_TYPE)).doesNotContainKey("2.5.4.3");
    }

    @Test
    void cacheOid_onUncachedCategory_doesNotThrow() {
        // Enforce the uncached precondition so the getOrDefault guard path is actually exercised,
        // rather than assuming the category happens to be absent in the shared JVM.
        evictCategory(OidCategory.GENERIC);
        assertThat(OidHandler.getOidCache(OidCategory.GENERIC)).isNull();

        assertThatCode(() -> OidHandler.cacheOid(OidCategory.GENERIC, "1.2.3.4",
                OidRecord.builder().displayName("x").build()))
                .doesNotThrowAnyException();
        assertThat(OidHandler.getOidCache(OidCategory.GENERIC)).containsKey("1.2.3.4");
    }

    @Test
    void removeCachedOid_onUncachedCategory_isNoOpAndLeavesCategoryNull() {
        evictCategory(OidCategory.EXTENDED_KEY_USAGE);
        assertThat(OidHandler.getOidCache(OidCategory.EXTENDED_KEY_USAGE)).isNull();

        assertThatCode(() -> OidHandler.removeCachedOid(OidCategory.EXTENDED_KEY_USAGE, "9.9.9"))
                .doesNotThrowAnyException();

        // Must not materialize an empty entry: callers read null as "category not loaded yet".
        assertThat(OidHandler.getOidCache(OidCategory.EXTENDED_KEY_USAGE)).isNull();
    }

    /**
     * Removes a category from the private static cache so an uncached ({@code null}) precondition
     * is deterministic. There is no public API to drop a whole category, so the guard tests reach
     * into the field directly — acceptable for white-box unit coverage in the same package.
     */
    @SuppressWarnings("unchecked")
    private static void evictCategory(OidCategory category) {
        try {
            Field field = OidHandler.class.getDeclaredField("oidCache");
            field.setAccessible(true);
            ((Map<OidCategory, ?>) field.get(null)).remove(category);
        } catch (ReflectiveOperationException e) {
            throw new IllegalStateException("Could not evict OID category for test setup", e);
        }
    }
}
