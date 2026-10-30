package com.otilm.core.oid;

import com.otilm.api.model.core.oid.OidCategory;
import com.otilm.api.model.core.oid.SystemOid;
import java.lang.reflect.Field;
import java.util.EnumMap;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * Pure unit coverage for the {@link OidHandler} RDN-code lookup and copy-on-write mutators — no Spring context.
 *
 * <p>
 * The OID cache is process-wide static state shared across the surefire JVM, so this class snapshots every category it
 * touches in {@code @BeforeAll} and restores it in {@code @AfterAll} (mirroring
 * {@code X509RequestContentRendererTest.ToX500Principal}) rather than leaking state into other test classes.
 */
class OidHandlerTest {

    private static final OidCategory[] TOUCHED = {
            OidCategory.RDN_ATTRIBUTE_TYPE,
            OidCategory.GENERIC,
            OidCategory.EXTENDED_KEY_USAGE};

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
                // Refresh the derived rdnCodeToOid index to empty before dropping the entry —
                // evictCategory bypasses refreshRdnCodeLookup, so a bare remove would leave the
                // index holding phantom codes from tests in this class. No-op for non-RDN categories.
                OidHandler.cacheOidCategory(category, new HashMap<>());
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
        OidHandler
                .cacheOid(OidCategory.RDN_ATTRIBUTE_TYPE, "1.2.840.113549.1.9.1",
                        OidRecord
                                .builder()
                                .displayName("Email")
                                .code("EMAIL")
                                .altCodes(List.of("E", "EMAILADDRESS"))
                                .build());

        assertThat(OidHandler.getOidForRdnCode("EMAIL")).isEqualTo("1.2.840.113549.1.9.1");
        assertThat(OidHandler.getOidForRdnCode("email")).isEqualTo("1.2.840.113549.1.9.1");
        assertThat(OidHandler.getOidForRdnCode("e")).isEqualTo("1.2.840.113549.1.9.1");
        assertThat(OidHandler.getOidForRdnCode("EmailAddress")).isEqualTo("1.2.840.113549.1.9.1");
    }

    @Test
    void getCodeToOidMap_isCaseInsensitiveAtTheSource() {
        // The authoring-time gate reads this map directly rather than the derived index, so it must
        // match the same way request-time resolution does — otherwise a mixed-case system code such
        // as PostalCode is rejected when authored in another casing but resolves fine at runtime.
        OidHandler
                .cacheOid(OidCategory.RDN_ATTRIBUTE_TYPE, "2.5.4.17",
                        OidRecord.builder().displayName("Postal Code").code("PostalCode").build());

        assertThat(OidHandler.getCodeToOidMap()).containsEntry("POSTALCODE", "2.5.4.17");
        assertThat(OidHandler.getCodeToOidMap()).containsEntry("postalcode", "2.5.4.17");
    }

    @Test
    void contestedRdnCode_resolvesToTheOperatorRegisteredEntry() {
        // given — a deployment registered its own OID under code UID before 0.9.2342.19200300.100.1.1
        // became a system OID. Both now claim the token.
        Map<String, OidRecord> rdn = new HashMap<>();
        rdn
                .put(SystemOid.USER_ID.getOid(),
                        OidRecord.builder().displayName("User ID").code("UID").system(true).build());
        rdn.put("1.2.3.4.5.6", OidRecord.builder().displayName("Legacy UID").code("UID").build());
        OidHandler.cacheOidCategory(OidCategory.RDN_ATTRIBUTE_TYPE, rdn);

        // when / then — the custom entry keeps the token; promoting an OID must not silently repoint
        // a DN that was already parsing to the operator's attribute type
        assertThat(OidHandler.getOidForRdnCode("UID")).isEqualTo("1.2.3.4.5.6");
        assertThat(OidHandler.getOidForRdnCode("uid")).isEqualTo("1.2.3.4.5.6");
    }

    @Test
    void contestedRdnCode_resolutionSurvivesAnUnrelatedCacheRebuild() {
        // given — the same contest as above
        Map<String, OidRecord> rdn = new HashMap<>();
        rdn
                .put(SystemOid.USER_ID.getOid(),
                        OidRecord.builder().displayName("User ID").code("UID").system(true).build());
        rdn.put("1.2.3.4.5.6", OidRecord.builder().displayName("Legacy UID").code("UID").build());
        OidHandler.cacheOidCategory(OidCategory.RDN_ATTRIBUTE_TYPE, rdn);
        String before = OidHandler.getOidForRdnCode("UID");

        // when — any unrelated custom-OID write rebuilds the derived index
        OidHandler
                .cacheOid(OidCategory.RDN_ATTRIBUTE_TYPE, "9.8.7.6",
                        OidRecord.builder().displayName("Unrelated").code("UNRELATED").build());

        // then — the winner must not flip; previously this depended on HashMap iteration order
        assertThat(OidHandler.getOidForRdnCode("UID")).isEqualTo(before).isEqualTo("1.2.3.4.5.6");
    }

    @Test
    void contestedRdnCode_isPublishedAsQueryableConflictState() {
        // given — the cache rebuilds every few seconds, so the conflict has to be readable state an
        // operator can be shown, not just a log line that repeats until it is filtered out
        Map<String, OidRecord> rdn = new HashMap<>();
        rdn
                .put(SystemOid.USER_ID.getOid(),
                        OidRecord.builder().displayName("User ID").code("UID").system(true).build());
        rdn.put("1.2.3.4.5.6", OidRecord.builder().displayName("Legacy UID").code("uid").build());
        OidHandler.cacheOidCategory(OidCategory.RDN_ATTRIBUTE_TYPE, rdn);

        // when / then — matched case-insensitively, and both claimants are named
        assertThat(OidHandler.getRdnCodeConflicts())
                .hasSize(1)
                .satisfies(conflicts -> assertThat(conflicts.values().iterator().next())
                        .containsExactlyInAnyOrder(SystemOid.USER_ID.getOid(), "1.2.3.4.5.6"));
    }

    @Test
    void publishedConflictState_isDeeplyImmutable() {
        // given — the conflict map is process-wide static state reachable through a public accessor, so
        // a caller must not be able to reach through the unmodifiable map into a mutable value set
        Map<String, OidRecord> rdn = new HashMap<>();
        rdn
                .put(SystemOid.USER_ID.getOid(),
                        OidRecord.builder().displayName("User ID").code("UID").system(true).build());
        rdn.put("1.2.3.4.5.6", OidRecord.builder().displayName("Legacy UID").code("UID").build());
        OidHandler.cacheOidCategory(OidCategory.RDN_ATTRIBUTE_TYPE, rdn);

        Set<String> claimants = OidHandler.getRdnCodeConflicts().get("UID");

        // when / then — mutating a claimant set would corrupt the shared state and break the
        // change-detection that keeps the warning from repeating on every rebuild
        assertThat(claimants).isNotNull();
        assertThatThrownBy(() -> claimants.add("9.9.9.9")).isInstanceOf(UnsupportedOperationException.class);
    }

    @Test
    void publishedConflictState_looksUpTokensCaseInsensitively() {
        // given — every other code lookup in the registry is case-insensitive; this one must agree or a
        // caller reading the conflict for "uid" silently sees nothing
        Map<String, OidRecord> rdn = new HashMap<>();
        rdn
                .put(SystemOid.USER_ID.getOid(),
                        OidRecord.builder().displayName("User ID").code("UID").system(true).build());
        rdn.put("1.2.3.4.5.6", OidRecord.builder().displayName("Legacy UID").code("UID").build());
        OidHandler.cacheOidCategory(OidCategory.RDN_ATTRIBUTE_TYPE, rdn);

        // when / then
        assertThat(OidHandler.getRdnCodeConflicts().get("uid")).isNotNull();
        assertThat(OidHandler.getRdnCodeConflicts().get("UID")).isNotNull();
    }

    @Test
    void contestBetweenTwoOperatorRows_keepsTheLexicographicallyFirstOid() {
        // given — the mirror of the evict arm: no built-in is involved, so provenance cannot break the
        // tie and only determinism is guaranteed
        Map<String, OidRecord> rdn = new HashMap<>();
        rdn.put("0.1.2.3", OidRecord.builder().displayName("First").code("DUP").build());
        rdn.put("9.8.7.6", OidRecord.builder().displayName("Second").code("DUP").build());
        OidHandler.cacheOidCategory(OidCategory.RDN_ATTRIBUTE_TYPE, rdn);

        // when / then
        assertThat(OidHandler.getOidForRdnCode("DUP")).isEqualTo("0.1.2.3");
        assertThat(OidHandler.getRdnCodeConflicts()).containsKey("DUP");
    }

    @Test
    void shadowedOperatorRowKeepsItsTokenAgainstAnotherOperatorRow() {
        // given — a custom row occupying a system OID, contested by a second custom row that sorts AFTER
        // it. The shadowed row therefore claims the token first, and keeps it only if provenance decides
        // the contest: classifying by OID identity would read it as built-in and evict it.
        Map<String, OidRecord> rdn = new HashMap<>();
        rdn.put(SystemOid.USER_ID.getOid(), OidRecord.builder().displayName("Shadowed row").code("DUP").build());
        rdn.put("1.2.3.4", OidRecord.builder().displayName("Other operator row").code("DUP").build());
        OidHandler.cacheOidCategory(OidCategory.RDN_ATTRIBUTE_TYPE, rdn);

        // when / then — neither record is built-in, so the first claimant keeps the token
        assertThat(OidHandler.getOidForRdnCode("DUP")).isEqualTo(SystemOid.USER_ID.getOid());
    }

    @Test
    void resolvingAContestedRdnCode_clearsTheConflictState() {
        // given — a contest that an operator then resolves by renaming their code
        Map<String, OidRecord> rdn = new HashMap<>();
        rdn
                .put(SystemOid.USER_ID.getOid(),
                        OidRecord.builder().displayName("User ID").code("UID").system(true).build());
        rdn.put("1.2.3.4.5.6", OidRecord.builder().displayName("Legacy UID").code("UID").build());
        OidHandler.cacheOidCategory(OidCategory.RDN_ATTRIBUTE_TYPE, rdn);
        assertThat(OidHandler.getRdnCodeConflicts()).isNotEmpty();

        // when
        rdn.put("1.2.3.4.5.6", OidRecord.builder().displayName("Legacy UID").code("LEGACYUID").build());
        OidHandler.cacheOidCategory(OidCategory.RDN_ATTRIBUTE_TYPE, rdn);

        // then
        assertThat(OidHandler.getRdnCodeConflicts()).isEmpty();
    }

    @Test
    void unambiguousRegistry_reportsNoConflicts() {
        OidHandler
                .cacheOid(OidCategory.RDN_ATTRIBUTE_TYPE, "2.5.4.3",
                        OidRecord.builder().displayName("Common Name").code("CN").build());

        assertThat(OidHandler.getRdnCodeConflicts()).isEmpty();
    }

    @Test
    void cacheAllCategories_abandonsAStaleSnapshot() {
        // given — a refresh read its source data, then a mutator published before the refresh could
        long staleGeneration = OidHandler.getGeneration();
        OidHandler
                .cacheOid(OidCategory.RDN_ATTRIBUTE_TYPE, "2.5.4.3",
                        OidRecord.builder().displayName("Common Name").code("CN").build());

        // when — the refresh tries to publish a snapshot that predates that mutation
        boolean published = OidHandler
                .cacheAllCategories(staleGeneration, Map.of(OidCategory.RDN_ATTRIBUTE_TYPE, Map.of()));

        // then — abandoned, so the committed mutation is not clobbered
        assertThat(published).isFalse();
        assertThat(OidHandler.getOidForRdnCode("CN")).isEqualTo("2.5.4.3");
    }

    @Test
    void cacheAllCategories_publishesWhenTheGenerationStillMatches() {
        // given
        OidHandler
                .cacheOid(OidCategory.RDN_ATTRIBUTE_TYPE, "2.5.4.3",
                        OidRecord.builder().displayName("Common Name").code("CN").build());
        long current = OidHandler.getGeneration();

        // when — a full swap of the category, replacing its contents
        boolean published = OidHandler
                .cacheAllCategories(current, Map
                        .of(OidCategory.RDN_ATTRIBUTE_TYPE,
                                Map.of("2.5.4.6", OidRecord.builder().displayName("Country").code("C").build())));

        // then — published, dropping what the snapshot did not contain, and the derived index is rebuilt
        assertThat(published).isTrue();
        assertThat(OidHandler.getOidForRdnCode("C")).isEqualTo("2.5.4.6");
        assertThat(OidHandler.getOidForRdnCode("CN")).isNull();
    }

    @Test
    void cacheAllCategories_leavesUnsuppliedCategoriesUntouched() {
        // given — a category absent from the snapshot must not be cleared: null means "not loaded" to
        // every reader, and PlatformX500NameStyle dereferences the RDN category without a null check
        OidHandler.cacheOid(OidCategory.GENERIC, "1.2.3.4", OidRecord.builder().displayName("kept").build());

        // when
        OidHandler.cacheAllCategories(OidHandler.getGeneration(), Map.of(OidCategory.RDN_ATTRIBUTE_TYPE, Map.of()));

        // then
        assertThat(OidHandler.getOidCache(OidCategory.GENERIC)).containsKey("1.2.3.4");
    }

    @Test
    void removeCachedOid_deregistersRdnCode() {
        OidHandler
                .cacheOid(OidCategory.RDN_ATTRIBUTE_TYPE, "2.5.4.3",
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

        assertThatCode(
                () -> OidHandler.cacheOid(OidCategory.GENERIC, "1.2.3.4", OidRecord.builder().displayName("x").build()))
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

    @Test
    void isOidAppliesTheArcRulesTheEncoderEnforces() {
        assertThat(OidHandler.isOid("1.2.3")).isTrue();
        assertThat(OidHandler.isOid("2.5.29.19")).isTrue();
        assertThat(OidHandler.isOid("2.999.1")).isTrue();
        assertThat(OidHandler.isOid("1.39")).isTrue();

        // A first arc of 0 or 1 caps the second at 39; BouncyCastle rejects these, so accepting them here
        // would defer the failure to the encoder.
        assertThat(OidHandler.isOid("1.40")).isFalse();
        assertThat(OidHandler.isOid("0.99")).isFalse();
        assertThat(OidHandler.isOid("3.2.1")).isFalse();
        assertThat(OidHandler.isOid("1")).isFalse();
        assertThat(OidHandler.isOid(null)).isFalse();
    }

    /**
     * Removes a category from the private static cache so an uncached ({@code null}) precondition is deterministic.
     * There is no public API to drop a whole category, so the guard tests reach into the field directly — acceptable
     * for white-box unit coverage in the same package.
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
