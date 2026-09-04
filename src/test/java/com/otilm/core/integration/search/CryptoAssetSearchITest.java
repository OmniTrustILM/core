package com.otilm.core.integration.search;

import com.otilm.api.exception.ValidationException;
import com.otilm.api.model.client.certificate.SearchFilterRequestDto;
import com.otilm.api.model.core.auth.Resource;
import com.otilm.api.model.core.cbom.CbomAssetSyncState;
import com.otilm.api.model.core.cryptoasset.CryptographicAssetType;
import com.otilm.api.model.core.cryptoasset.PqcVerdict;
import com.otilm.api.model.core.search.FilterConditionOperator;
import com.otilm.core.attribute.engine.AttributeEngine.CustomAttributeContentFilter;
import com.otilm.core.cbom.asset.AssetRowKeys;
import com.otilm.core.cbom.asset.CryptoAssetIdentityFields;
import com.otilm.core.dao.entity.Cbom;
import com.otilm.core.dao.entity.cbom.CryptoAsset;
import com.otilm.core.dao.repository.CbomRepository;
import com.otilm.core.dao.repository.cbom.CryptoAssetRepository;
import com.otilm.core.enums.FilterField;
import com.otilm.core.model.cbom.CryptoAssetIdentityGuard;
import com.otilm.core.security.authz.SecurityFilter;
import com.otilm.core.service.writer.cbom.CbomAssetSyncStateWriter;
import com.otilm.core.service.writer.cbom.CryptoAssetSourceWriter;
import com.otilm.core.service.writer.cbom.CryptoAssetWriter;
import com.otilm.core.util.BaseSpringBootTest;
import com.otilm.core.util.FilterPredicatesBuilder;
import java.io.Serializable;
import java.time.OffsetDateTime;
import java.time.format.DateTimeFormatter;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.function.Supplier;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.domain.PageRequest;

import static com.otilm.core.util.builders.SearchFilterRequestDtoBuilder.aPropertyEmptyFilter;
import static com.otilm.core.util.builders.SearchFilterRequestDtoBuilder.aPropertyEqualsFilter;
import static com.otilm.core.util.builders.SearchFilterRequestDtoBuilder.aPropertyFilter;
import static com.otilm.core.util.builders.SearchFilterRequestDtoBuilder.aPropertyNotEmptyFilter;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * Every crypto-asset search field, exercised against real PostgreSQL for the three cases a nullable column makes
 * distinct: a value match, no value at all, and any value.
 *
 * <p>
 * Nearly every identity column is nullable, because a producer may omit any of them, and a predicate that silently
 * fails to distinguish "absent" from "does not match" would make a filter quietly wrong rather than loudly broken. The
 * enum-backed columns are exercised too: the filter value arrives as text, and whether that text compares correctly
 * against an enum-mapped column is a fact about Hibernate, not something to assume.
 */
class CryptoAssetSearchITest extends BaseSpringBootTest {

    /** No attribute-content restriction: these cases pin predicate shape, not authorization. */
    private static final Supplier<CustomAttributeContentFilter> UNRESTRICTED_ATTRIBUTE_CONTENT = () -> new CustomAttributeContentFilter(
            null, null);

    @Autowired
    private CryptoAssetRepository assetRepository;

    @Autowired
    private CryptoAssetWriter assetWriter;

    @Autowired
    private CryptoAssetSourceWriter sourceWriter;

    @Autowired
    private CbomRepository cbomRepository;

    @Autowired
    private CbomAssetSyncStateWriter syncStateWriter;

    private UUID populated;
    private UUID bare;

    @BeforeEach
    void seedAssets() {
        populated = upsert(new CryptoAssetIdentityFields(CryptographicAssetType.ALGORITHM, "ECDSA",
                "1.2.840.10045.4.3.2", "ecdsa", "signature", "P-256", "secp256r1", "cbc", "pkcs1v15", "fips186-4"),
                null);
        bare = upsert(new CryptoAssetIdentityFields(CryptographicAssetType.CERTIFICATE, null, null, null, null, null,
                null, null, null, null), null);

        assetWriter
                .applyPqcVerdict(populated, PqcVerdict.NOT_READY, "ECDSA-CLASSICAL", "not quantum resistant", 3,
                        java.util.Map.of("curve", "P-256"));
    }

    // ---- the identity and filter columns ----

    /**
     * The expected values are the <em>canonical</em> spellings, not the ones the seed passed in: the row stores
     * {@link CryptoAssetIdentityFields#normalized()}, so a seed of {@code "ECDSA"} is matched by {@code "ecdsa"}. That
     * is the visible consequence of the row being a deduplicated view rather than one producer's text.
     */
    @Test
    void everyNullableTextFieldDistinguishesAValueMatchFromAnAbsentValue() {
        assertFieldBehaviour(FilterField.CBOM_ASSET_NAME, "ecdsa");
        assertFieldBehaviour(FilterField.CBOM_ASSET_OID, "1.2.840.10045.4.3.2");
        assertFieldBehaviour(FilterField.CBOM_ASSET_ALGORITHM_FAMILY, "ecdsa");
        assertFieldBehaviour(FilterField.CBOM_ASSET_PRIMITIVE, "signature");
        assertFieldBehaviour(FilterField.CBOM_ASSET_PARAMETER_SET, "p-256");
        assertFieldBehaviour(FilterField.CBOM_ASSET_CURVE, "secp256r1");
        assertFieldBehaviour(FilterField.CBOM_ASSET_MODE, "cbc");
        assertFieldBehaviour(FilterField.CBOM_ASSET_PADDING, "pkcs1v15");
        assertFieldBehaviour(FilterField.CBOM_ASSET_VARIANT, "fips186-4");
    }

    /**
     * The finding this storage rule exists for. Two producers report one asset with different spellings, and one sends
     * whitespace where the other sent nothing. Both key to the same row, so whichever synced last used to decide what
     * an EQUALS predicate matched and whether the row counted as empty on that field.
     *
     * <p>
     * The assertions are written out rather than delegated to {@link #assertFieldBehaviour}: that helper is bound to
     * the seeded {@code populated} row, and the row under test here is a third one.
     */
    @Test
    void aFilterAnswerDoesNotDependOnWhichProducerSyncedLast() {
        UUID first = upsert(new CryptoAssetIdentityFields(CryptographicAssetType.ALGORITHM, "AES", null, null, null,
                null, null, "GCM", null, null), null);
        UUID second = upsert(new CryptoAssetIdentityFields(CryptographicAssetType.ALGORITHM, "  aes  ", "   ", null,
                null, null, null, " gcm ", null, null), null);

        assertThat(second).describedAs("both spellings key to one row").isEqualTo(first);
        assertThat(search(aPropertyEqualsFilter(FilterField.CBOM_ASSET_NAME, "aes")))
                .describedAs("EQUALS on the canonical name, whichever producer synced last")
                .containsExactly(first);
        assertThat(search(aPropertyEqualsFilter(FilterField.CBOM_ASSET_MODE, "gcm")))
                .describedAs("EQUALS on the canonical mode, whichever producer synced last")
                .containsExactly(first);
        assertThat(search(aPropertyEmptyFilter(FilterField.CBOM_ASSET_OID)))
                .describedAs("a field one producer omitted and another sent blank stays absent, so EMPTY is stable")
                .containsExactlyInAnyOrder(bare, first);
    }

    /**
     * The wire carries the contract code ({@code notReady}), not the persisted constant name ({@code NOT_READY}).
     * Declaring {@code enumClass} is what makes the builder resolve one to the other, so this pins that the two forms
     * are wired together rather than accidentally identical.
     */
    @Test
    void theEnumBackedVerdictColumnMatchesTheContractCode() {
        assertFieldBehaviour(FilterField.CBOM_ASSET_PQC_VERDICT, PqcVerdict.NOT_READY.getCode());
    }

    @Test
    void theNullablePqcRulesetVersionDistinguishesAValueMatchFromAnAbsentValue() {
        assertFieldBehaviour(FilterField.CBOM_ASSET_PQC_RULESET_VERSION, "3");
    }

    @Test
    void theNotNullAssetTypeMatchesByValueAndIsNeverEmpty() {
        assertThat(
                search(aPropertyEqualsFilter(FilterField.CBOM_ASSET_TYPE, CryptographicAssetType.ALGORITHM.getCode())))
                .containsExactly(populated);
        assertThat(search(
                aPropertyEqualsFilter(FilterField.CBOM_ASSET_TYPE, CryptographicAssetType.CERTIFICATE.getCode())))
                .containsExactly(bare);
        assertThat(search(aPropertyEmptyFilter(FilterField.CBOM_ASSET_TYPE))).isEmpty();
        assertThat(search(aPropertyNotEmptyFilter(FilterField.CBOM_ASSET_TYPE)))
                .containsExactlyInAnyOrder(populated, bare);
    }

    @Test
    void theNotNullNumericColumnsMatchByValueAndComparison() {
        assertThat(search(aPropertyEqualsFilter(FilterField.CBOM_ASSET_SOURCE_COUNT, "0")))
                .containsExactlyInAnyOrder(populated, bare);
        assertThat(search(aPropertyEqualsFilter(FilterField.CBOM_ASSET_SOURCE_COUNT, "1"))).isEmpty();
        assertThat(
                search(aPropertyFilter(FilterField.CBOM_ASSET_RULESET_VERSION, FilterConditionOperator.GREATER, "0")))
                .containsExactlyInAnyOrder(populated, bare);
        assertThat(search(aPropertyEmptyFilter(FilterField.CBOM_ASSET_RULESET_VERSION))).isEmpty();
    }

    @Test
    void aFilterCombinesWithAnother() {
        assertThat(searchAll(List
                .of(aPropertyEqualsFilter(FilterField.CBOM_ASSET_TYPE, CryptographicAssetType.ALGORITHM.getCode()),
                        aPropertyEqualsFilter(FilterField.CBOM_ASSET_CURVE, "secp256r1"))))
                .containsExactly(populated);
        assertThat(searchAll(List
                .of(aPropertyEqualsFilter(FilterField.CBOM_ASSET_TYPE, CryptographicAssetType.CERTIFICATE.getCode()),
                        aPropertyEqualsFilter(FilterField.CBOM_ASSET_CURVE, "secp256r1"))))
                .isEmpty();
    }

    // ---- free text, refuted-OID and source-CBOM filters ----

    @Test
    void freeTextMatchesNameAndOidCaseInsensitively() {
        assertThat(search(aPropertyFilter(FilterField.CBOM_ASSET_FREE_TEXT, FilterConditionOperator.CONTAINS, "ECDSA")))
                .describedAs("matches the name despite the case difference from the stored canonical spelling")
                .containsExactly(populated);
        assertThat(search(aPropertyFilter(FilterField.CBOM_ASSET_FREE_TEXT, FilterConditionOperator.CONTAINS, "10045")))
                .describedAs("matches the oid")
                .containsExactly(populated);
    }

    /**
     * The issue's acceptance criterion: a refuted OID is stored and auditable, but a default free-text search must
     * never let it answer a query, while the row itself stays findable through every other property.
     */
    @Test
    void freeTextNeverMatchesThroughARefutedOidWithoutTheOptIn() {
        UUID refuted = upsert(new CryptoAssetIdentityFields(CryptographicAssetType.ALGORITHM, "ML-KEM-768",
                "2.16.840.1.101.3.4.4.2", "ml-kem", "kem", null, null, null, null, null),
                CryptoAssetIdentityGuard.REFUTED_OID);

        assertThat(search(
                aPropertyFilter(FilterField.CBOM_ASSET_FREE_TEXT, FilterConditionOperator.CONTAINS, "101.3.4.4")))
                .describedAs("the refuted oid is the row's only match, so a default search must not surface it")
                .isEmpty();
        assertThat(
                search(aPropertyFilter(FilterField.CBOM_ASSET_FREE_TEXT, FilterConditionOperator.CONTAINS, "ml-kem")))
                .describedAs("the row is not hidden -- only its refuted oid is neutralized, the name still matches")
                .containsExactly(refuted);
        assertThat(searchAll(List
                .of(aPropertyFilter(FilterField.CBOM_ASSET_FREE_TEXT, FilterConditionOperator.CONTAINS, "101.3.4.4"),
                        aPropertyEqualsFilter(FilterField.CBOM_ASSET_OID_REFUTED, "true"))))
                .describedAs("opting into the refuted-OID facet lets the neutralized value answer again")
                .containsExactly(refuted);
    }

    @Test
    void freeTextRefusesEveryOperatorExceptContains() {
        SearchFilterRequestDto equalsOperator = aPropertyFilter(FilterField.CBOM_ASSET_FREE_TEXT,
                FilterConditionOperator.EQUALS, "ecdsa");
        assertThatThrownBy(() -> search(equalsOperator)).isInstanceOf(ValidationException.class);
    }

    /**
     * The same acceptance criterion as {@link #freeTextNeverMatchesThroughARefutedOidWithoutTheOptIn}, exercised
     * directly against the OID field's own value predicates rather than through free text.
     */
    @Test
    void oidValuePredicatesTreatARefutedOidAsAbsent() {
        UUID refuted = upsert(new CryptoAssetIdentityFields(CryptographicAssetType.ALGORITHM, "ML-KEM-768",
                "2.16.840.1.101.3.4.4.2", "ml-kem", "kem", null, null, null, null, null),
                CryptoAssetIdentityGuard.REFUTED_OID);

        assertThat(search(aPropertyEqualsFilter(FilterField.CBOM_ASSET_OID, "2.16.840.1.101.3.4.4.2")))
                .describedAs("a refuted oid must not answer an EQUALS predicate")
                .isEmpty();
        assertThat(searchAll(List
                .of(aPropertyEqualsFilter(FilterField.CBOM_ASSET_OID, "2.16.840.1.101.3.4.4.2"),
                        aPropertyEqualsFilter(FilterField.CBOM_ASSET_OID_REFUTED, "true"))))
                .describedAs("opting into the refuted-OID facet lets the recorded value answer again")
                .containsExactly(refuted);
        assertThat(search(aPropertyFilter(FilterField.CBOM_ASSET_OID, FilterConditionOperator.CONTAINS, "101.3.4")))
                .describedAs("a refuted oid must not answer a CONTAINS predicate")
                .isEmpty();
        assertThat(search(
                aPropertyFilter(FilterField.CBOM_ASSET_OID, FilterConditionOperator.NOT_EQUALS, "1.2.840.10045.4.3.2")))
                .describedAs("a NULL oid satisfies NOT_EQUALS for any value, and a refuted one must too")
                .containsExactlyInAnyOrder(refuted, bare);
        assertThat(search(aPropertyEmptyFilter(FilterField.CBOM_ASSET_OID)))
                .describedAs("the refuted row HAS a recorded oid, so it is not EMPTY")
                .containsExactly(bare);
        assertThat(search(aPropertyNotEmptyFilter(FilterField.CBOM_ASSET_OID)))
                .describedAs("the recorded value stays auditable under NOT_EMPTY")
                .containsExactlyInAnyOrder(populated, refuted);

        // The remaining value-bearing operators reach the same carve-out sets: every positive shape answers as if
        // the oid were absent, every negative shape admits the refuted row exactly as it admits a NULL oid.
        assertThat(search(aPropertyFilter(FilterField.CBOM_ASSET_OID, FilterConditionOperator.STARTS_WITH, "2.16.840")))
                .isEmpty();
        assertThat(search(aPropertyFilter(FilterField.CBOM_ASSET_OID, FilterConditionOperator.ENDS_WITH, "3.4.4.2")))
                .isEmpty();
        assertThat(
                search(aPropertyFilter(FilterField.CBOM_ASSET_OID, FilterConditionOperator.MATCHES, "^2\\.16\\.840.*")))
                .isEmpty();
        assertThat(search(
                aPropertyFilter(FilterField.CBOM_ASSET_OID, FilterConditionOperator.NOT_MATCHES, "^1\\.2\\.840.*")))
                .describedAs("NOT_MATCHES never matches a NULL oid, so the refuted row is excluded the same way")
                .isEmpty();
        assertThat(search(aPropertyFilter(FilterField.CBOM_ASSET_OID, FilterConditionOperator.NOT_CONTAINS, "1.2.840")))
                .describedAs("NOT_CONTAINS admits a NULL oid, so it admits the refuted row too")
                .containsExactlyInAnyOrder(refuted, bare);
    }

    @Test
    void theSourceCbomFilterRefusesConditionsItDoesNotAdvertise() {
        SearchFilterRequestDto contains = aPropertyFilter(FilterField.CBOM_ASSET_SOURCE_CBOM,
                FilterConditionOperator.CONTAINS, "urn:uuid:a");
        assertThatThrownBy(() -> search(contains)).isInstanceOf(ValidationException.class);
    }

    @Test
    void freeTextRequiresAValue() {
        SearchFilterRequestDto valueless = aPropertyFilter(FilterField.CBOM_ASSET_FREE_TEXT,
                FilterConditionOperator.CONTAINS, null);
        assertThatThrownBy(() -> search(valueless)).isInstanceOf(ValidationException.class);
    }

    @Test
    void theRefutedFacetSelectsRowsByRefutedness() {
        UUID refuted = upsert(new CryptoAssetIdentityFields(CryptographicAssetType.ALGORITHM, "ML-KEM-768",
                "2.16.840.1.101.3.4.4.2", "ml-kem", "kem", null, null, null, null, null),
                CryptoAssetIdentityGuard.REFUTED_OID);
        UUID bareCn = upsert(new CryptoAssetIdentityFields(CryptographicAssetType.CERTIFICATE, "some-cn", null, null,
                null, null, null, null, null, null), CryptoAssetIdentityGuard.BARE_CN_SUBJECT);

        assertThat(search(aPropertyEqualsFilter(FilterField.CBOM_ASSET_OID_REFUTED, "true")))
                .describedAs("only the refuted-OID row, not the BARE_CN_SUBJECT one")
                .containsExactly(refuted);
        assertThat(search(aPropertyEqualsFilter(FilterField.CBOM_ASSET_OID_REFUTED, "false")))
                .describedAs("everything else, including a differently-guarded row")
                .containsExactlyInAnyOrder(bareCn, bare, populated);
    }

    /**
     * The facet advertises EQUALS and NOT_EQUALS only. A hand-built request with another condition must be refused with
     * a shaped error: EMPTY used to reach the boolean value prep with no value (an NPE, so a 500), and NOT_EMPTY would
     * have read "any guard is set" as "OID refuted" while silently switching the refuted carve-outs off for the whole
     * request.
     */
    @Test
    void theRefutedFacetRefusesConditionsItDoesNotAdvertise() {
        SearchFilterRequestDto empty = aPropertyEmptyFilter(FilterField.CBOM_ASSET_OID_REFUTED);
        assertThatThrownBy(() -> search(empty)).isInstanceOf(ValidationException.class).hasMessageContaining("EMPTY");
        SearchFilterRequestDto notEmpty = aPropertyNotEmptyFilter(FilterField.CBOM_ASSET_OID_REFUTED);
        assertThatThrownBy(() -> search(notEmpty))
                .isInstanceOf(ValidationException.class)
                .hasMessageContaining("NOT_EMPTY");
    }

    /**
     * The facet's value must be a scalar boolean. The platform's expectedValue path parses
     * {@code getValue().toString()} with {@code Boolean.parseBoolean}, so a JSON-array value like ["true"] stringifies
     * to "[true]", parses false, and silently INVERTS the predicate -- while the facet's mere presence disarms the
     * refuted carve-outs for the whole request. The compound serves exclusively refuted rows to a caller whose intent
     * was to exclude them. Anything but a scalar "true"/"false" is refused with a shaped 422.
     */
    @Test
    void theRefutedFacetRefusesNonScalarAndNonBooleanValues() {
        upsert(new CryptoAssetIdentityFields(CryptographicAssetType.ALGORITHM, "ML-KEM-768", "2.16.840.1.101.3.4.4.2",
                "ml-kem", "kem", null, null, null, null, null), CryptoAssetIdentityGuard.REFUTED_OID);

        SearchFilterRequestDto arrayValued = aPropertyFilter(FilterField.CBOM_ASSET_OID_REFUTED,
                FilterConditionOperator.NOT_EQUALS, (Serializable) List.of("true"));
        SearchFilterRequestDto freeText = aPropertyFilter(FilterField.CBOM_ASSET_FREE_TEXT,
                FilterConditionOperator.CONTAINS, "101.3.4.4");
        assertThatThrownBy(() -> searchAll(List.of(freeText, arrayValued)))
                .describedAs("an array-valued facet must be refused, never inverted into 'refuted rows only' with "
                        + "the carve-outs disarmed")
                .isInstanceOf(ValidationException.class);

        SearchFilterRequestDto garbage = aPropertyEqualsFilter(FilterField.CBOM_ASSET_OID_REFUTED, "yes");
        assertThatThrownBy(() -> search(garbage))
                .describedAs("'yes' is not a boolean; parseBoolean would silently read it as false")
                .isInstanceOf(ValidationException.class);
    }

    /** Free text is advertised as a single-value field; extra values are refused rather than silently dropped. */
    @Test
    void freeTextRefusesAMultiValuePayload() {
        SearchFilterRequestDto multiValued = aPropertyFilter(FilterField.CBOM_ASSET_FREE_TEXT,
                FilterConditionOperator.CONTAINS, (Serializable) List.of("aes", "rsa"));
        assertThatThrownBy(() -> search(multiValued)).isInstanceOf(ValidationException.class);
    }

    /**
     * LIKE's wildcards are not part of the free-text contract: the search string matches literally, so an underscore in
     * producer vocabulary ("AES_128") cannot over-match lookalikes and a lone percent cannot dump the inventory.
     */
    @Test
    void freeTextTreatsLikeWildcardsAsLiteralText() {
        UUID underscored = upsert(new CryptoAssetIdentityFields(CryptographicAssetType.ALGORITHM, "AES_128",
                "oid-underscore", null, null, null, null, null, null, null), null);
        upsert(new CryptoAssetIdentityFields(CryptographicAssetType.ALGORITHM, "AESX128", "oid-lookalike", null, null,
                null, null, null, null, null), null);
        UUID percented = upsert(new CryptoAssetIdentityFields(CryptographicAssetType.ALGORITHM, "50% legacy",
                "oid-percent", null, null, null, null, null, null, null), null);

        assertThat(search(aPropertyFilter(FilterField.CBOM_ASSET_FREE_TEXT, FilterConditionOperator.CONTAINS, "s_1")))
                .describedAs("an underscore matches a literal underscore, not any character")
                .containsExactly(underscored);
        assertThat(search(aPropertyFilter(FilterField.CBOM_ASSET_FREE_TEXT, FilterConditionOperator.CONTAINS, "%")))
                .describedAs("the positive control: a lone percent matches exactly the row with a literal percent, "
                        + "not the whole inventory")
                .containsExactly(percented);
        assertThat(search(aPropertyFilter(FilterField.CBOM_ASSET_FREE_TEXT, FilterConditionOperator.CONTAINS, "0% l")))
                .describedAs("a percent inside a longer literal still matches literally")
                .containsExactly(percented);
    }

    @Test
    void theSourceCbomFilterMatchesThroughSourcesWithoutDuplicatingRows() {
        Cbom alpha = newCbom("urn:uuid:alpha");
        Cbom beta = newCbom("urn:uuid:beta");
        UUID other = upsert(new CryptoAssetIdentityFields(CryptographicAssetType.ALGORITHM, "RSA", null, "rsa",
                "signature", null, null, null, null, null), null);
        sourceWriter.upsertSource(populated, alpha.getUuid(), Map.of("k", "v"), List.of(), OffsetDateTime.now());
        sourceWriter.upsertSource(populated, beta.getUuid(), Map.of("k", "v"), List.of(), OffsetDateTime.now());
        sourceWriter.upsertSource(other, beta.getUuid(), Map.of("k", "v"), List.of(), OffsetDateTime.now());

        assertThat(search(aPropertyEqualsFilter(FilterField.CBOM_ASSET_SOURCE_CBOM, "urn:uuid:alpha")))
                .containsExactly(populated);
        SearchFilterRequestDto matchesEitherSerial = aPropertyEqualsFilter(FilterField.CBOM_ASSET_SOURCE_CBOM,
                (Serializable) List.of("urn:uuid:alpha", "urn:uuid:beta"));
        assertThat(search(matchesEitherSerial))
                .describedAs("populated has two matching sources; EQUALS matches through either")
                .containsExactlyInAnyOrder(populated, other);
        // findUsingSecurityFilter (used by search() above) runs its query through
        // SecurityFilterRepositoryImpl#createCriteriaBuilder, which selects DISTINCT and would hide a
        // join-based reimplementation of this predicate repeating populated's row. The uuid page query
        // -- createCriteriaBuilderUuid, reached only through findUuidsUsingSecurityFilter -- carries no
        // DISTINCT, so it is the path that actually proves the EXISTS design does not duplicate.
        List<UUID> undistinctedUuidPage = assetRepository
                .findUuidsUsingSecurityFilter(SecurityFilter.create(),
                        (root, cb, cr) -> FilterPredicatesBuilder
                                .getFiltersPredicate(cb, cr, root, List.of(matchesEitherSerial),
                                        UNRESTRICTED_ATTRIBUTE_CONTENT),
                        PageRequest.of(0, 10), (root, cb) -> cb.asc(root.get("uuid")));
        assertThat(undistinctedUuidPage)
                .describedAs("the undistincted uuid page must not repeat populated's row either")
                .containsExactlyInAnyOrder(populated, other);
        assertThat(search(aPropertyFilter(FilterField.CBOM_ASSET_SOURCE_CBOM, FilterConditionOperator.NOT_EQUALS,
                "urn:uuid:alpha"))).describedAs("rows without an alpha source").containsExactlyInAnyOrder(other, bare);
        assertThat(search(aPropertyEmptyFilter(FilterField.CBOM_ASSET_SOURCE_CBOM)))
                .describedAs("the sourceless row")
                .containsExactly(bare);
        assertThat(search(aPropertyNotEmptyFilter(FilterField.CBOM_ASSET_SOURCE_CBOM)))
                .describedAs("exactly the two sourced rows")
                .containsExactlyInAnyOrder(populated, other);
    }

    @Test
    void aFilterCombinesWithTheNewFields() {
        Cbom alpha = newCbom("urn:uuid:alpha");
        sourceWriter.upsertSource(populated, alpha.getUuid(), Map.of("k", "v"), List.of(), OffsetDateTime.now());

        assertThat(searchAll(List
                .of(aPropertyEqualsFilter(FilterField.CBOM_ASSET_TYPE, CryptographicAssetType.ALGORITHM.getCode()),
                        aPropertyFilter(FilterField.CBOM_ASSET_FREE_TEXT, FilterConditionOperator.CONTAINS, "ecdsa"),
                        aPropertyEqualsFilter(FilterField.CBOM_ASSET_SOURCE_CBOM, "urn:uuid:alpha"))))
                .containsExactly(populated);
    }

    // ---- the CBOM-rooted asset-sync fields ----

    @Test
    void theCbomAssetSyncFieldsAreRoutableFromTheCbomResource() {
        Cbom pending = newCbom("urn:uuid:pending");
        Cbom synced = newCbom("urn:uuid:synced");
        OffsetDateTime syncedAt = OffsetDateTime.now();
        syncStateWriter.markSynced(synced.getUuid(), syncedAt);

        assertThat(FilterField.getEnumsForResource(Resource.CBOM))
                .contains(FilterField.CBOM_ASSET_SYNC_STATE, FilterField.CBOM_ASSETS_SYNCED_AT);

        assertThat(searchCbom(
                aPropertyEqualsFilter(FilterField.CBOM_ASSET_SYNC_STATE, CbomAssetSyncState.PENDING.getCode())))
                .containsExactly(pending.getUuid());
        assertThat(searchCbom(
                aPropertyEqualsFilter(FilterField.CBOM_ASSET_SYNC_STATE, CbomAssetSyncState.SYNCED.getCode())))
                .containsExactly(synced.getUuid());
        assertThat(searchCbom(aPropertyEmptyFilter(FilterField.CBOM_ASSETS_SYNCED_AT)))
                .containsExactly(pending.getUuid());
        assertThat(searchCbom(aPropertyNotEmptyFilter(FilterField.CBOM_ASSETS_SYNCED_AT)))
                .containsExactly(synced.getUuid());
        assertThat(searchCbom(aPropertyFilter(FilterField.CBOM_ASSETS_SYNCED_AT, FilterConditionOperator.LESSER,
                syncedAt.plusDays(1).format(DateTimeFormatter.ofPattern("yyyy-MM-dd'T'HH:mm:ssXXX")))))
                .containsExactly(synced.getUuid());
    }

    // ---- the ratified search surface ----

    @Test
    void theCryptoAssetFieldsAreRoutableUnderTheirOwnResource() {
        List<FilterField> cryptoAssetFields = Arrays
                .stream(FilterField.values())
                .filter(field -> field.getFieldAttribute() != null)
                .filter(field -> field.getFieldAttribute().getDeclaringType().getJavaType() == CryptoAsset.class)
                .toList();

        assertThat(cryptoAssetFields)
                .describedAs("the whole crypto-asset filter set is declared, and identity_key is not in it")
                .containsExactly(FilterField.CBOM_ASSET_TYPE, FilterField.CBOM_ASSET_NAME, FilterField.CBOM_ASSET_OID,
                        FilterField.CBOM_ASSET_ALGORITHM_FAMILY, FilterField.CBOM_ASSET_PRIMITIVE,
                        FilterField.CBOM_ASSET_PARAMETER_SET, FilterField.CBOM_ASSET_CURVE, FilterField.CBOM_ASSET_MODE,
                        FilterField.CBOM_ASSET_PADDING, FilterField.CBOM_ASSET_VARIANT,
                        FilterField.CBOM_ASSET_PQC_VERDICT, FilterField.CBOM_ASSET_PQC_RULESET_VERSION,
                        FilterField.CBOM_ASSET_RULESET_VERSION, FilterField.CBOM_ASSET_SOURCE_COUNT,
                        FilterField.CBOM_ASSET_OID_REFUTED);
        assertThat(cryptoAssetFields)
                .describedAs("every crypto-asset field roots at the ratified CRYPTO_ASSET resource, so the inventory "
                        + "gets its own search surface rather than borrowing the CBOM one")
                .allSatisfy(field -> assertThat(field.getRootResource()).isEqualTo(Resource.CRYPTO_ASSET));
        // FREE_TEXT has no fieldAttribute and SOURCE_CBOM's declares on Cbom, not CryptoAsset, so neither is in
        // cryptoAssetFields above; both still root at CRYPTO_ASSET and belong in its declared search surface.
        assertThat(FilterField.getEnumsForResource(Resource.CRYPTO_ASSET))
                .describedAs("CRYPTO_ASSET serves the crypto-asset fields and nothing else")
                .containsExactly(FilterField.CBOM_ASSET_TYPE, FilterField.CBOM_ASSET_NAME, FilterField.CBOM_ASSET_OID,
                        FilterField.CBOM_ASSET_ALGORITHM_FAMILY, FilterField.CBOM_ASSET_PRIMITIVE,
                        FilterField.CBOM_ASSET_PARAMETER_SET, FilterField.CBOM_ASSET_CURVE, FilterField.CBOM_ASSET_MODE,
                        FilterField.CBOM_ASSET_PADDING, FilterField.CBOM_ASSET_VARIANT,
                        FilterField.CBOM_ASSET_PQC_VERDICT, FilterField.CBOM_ASSET_PQC_RULESET_VERSION,
                        FilterField.CBOM_ASSET_RULESET_VERSION, FilterField.CBOM_ASSET_SOURCE_COUNT,
                        FilterField.CBOM_ASSET_FREE_TEXT, FilterField.CBOM_ASSET_OID_REFUTED,
                        FilterField.CBOM_ASSET_SOURCE_CBOM);

        for (Resource resource : Resource.values()) {
            if (resource == Resource.CRYPTO_ASSET) {
                continue;
            }
            assertThat(FilterField.getEnumsForResource(resource))
                    .describedAs("resource %s", resource)
                    .doesNotContainAnyElementsOf(cryptoAssetFields);
        }
    }

    @Test
    void theEnumBackedCryptoAssetFieldsCarryTheirContractEnum() {
        assertThat(FilterField.CBOM_ASSET_TYPE.getEnumClass()).isEqualTo(CryptographicAssetType.class);
        assertThat(FilterField.CBOM_ASSET_PQC_VERDICT.getEnumClass()).isEqualTo(PqcVerdict.class);
        assertThat(FilterField.CBOM_ASSET_SYNC_STATE.getEnumClass()).isEqualTo(CbomAssetSyncState.class);
    }

    // ---- helpers ----

    private void assertFieldBehaviour(FilterField field, Serializable matchingValue) {
        assertThat(search(aPropertyEqualsFilter(field, matchingValue)))
                .describedAs("EQUALS on %s", field)
                .containsExactly(populated);
        assertThat(search(aPropertyEmptyFilter(field))).describedAs("EMPTY on %s", field).containsExactly(bare);
        assertThat(search(aPropertyNotEmptyFilter(field)))
                .describedAs("NOT_EMPTY on %s", field)
                .containsExactly(populated);
    }

    private List<UUID> search(SearchFilterRequestDto filter) {
        return searchAll(List.of(filter));
    }

    private List<UUID> searchAll(List<SearchFilterRequestDto> filters) {
        return assetRepository
                .findUsingSecurityFilter(SecurityFilter.create(), List.of(),
                        (root, cb, cr) -> FilterPredicatesBuilder
                                .getFiltersPredicate(cb, cr, root, filters, UNRESTRICTED_ATTRIBUTE_CONTENT))
                .stream()
                .map(CryptoAsset::getUuid)
                .toList();
    }

    private List<UUID> searchCbom(SearchFilterRequestDto filter) {
        return cbomRepository
                .findUsingSecurityFilter(SecurityFilter.create(), List.of(),
                        (root, cb, cr) -> FilterPredicatesBuilder
                                .getFiltersPredicate(cb, cr, root, List.of(filter), UNRESTRICTED_ATTRIBUTE_CONTENT))
                .stream()
                .map(Cbom::getUuid)
                .toList();
    }

    private Cbom newCbom(String serialNumber) {
        Cbom cbom = new Cbom();
        cbom.setSerialNumber(serialNumber);
        cbom.setVersion(1);
        cbom.setSpecVersion("1.7");
        return cbomRepository.save(cbom);
    }

    /**
     * Upserts through the writer with a fixture key derived from the fields.
     *
     * <p>
     * The writer no longer computes the key -- the extraction pipeline does, from the whole component -- so a
     * persistence test has to supply one. {@link AssetRowKeys} makes it a stable function of the normalized fields,
     * which is what keeps every dedup assertion below meaning what it meant before.
     */
    private UUID upsert(CryptoAssetIdentityFields fields, CryptoAssetIdentityGuard guard) {
        return assetWriter.upsertIdentity(AssetRowKeys.forFields(fields), fields, guard);
    }
}
