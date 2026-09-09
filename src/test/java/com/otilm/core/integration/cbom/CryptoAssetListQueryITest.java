package com.otilm.core.integration.cbom;

import com.otilm.api.model.client.certificate.SearchFilterRequestDto;
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
import com.otilm.core.model.cbom.CryptoAssetListRow;
import com.otilm.core.security.authz.SecurityFilter;
import com.otilm.core.service.writer.cbom.CryptoAssetSourceWriter;
import com.otilm.core.service.writer.cbom.CryptoAssetWriter;
import com.otilm.core.util.BaseSpringBootTest;
import com.otilm.core.util.FilterPredicatesBuilder;
import jakarta.persistence.criteria.CriteriaBuilder;
import jakarta.persistence.criteria.CriteriaQuery;
import jakarta.persistence.criteria.Order;
import jakarta.persistence.criteria.Predicate;
import jakarta.persistence.criteria.Root;
import java.io.Serializable;
import java.time.OffsetDateTime;
import java.util.Arrays;
import java.util.Comparator;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.function.BiFunction;
import java.util.function.Supplier;
import org.apache.commons.lang3.function.TriFunction;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.domain.PageRequest;

import static com.otilm.core.util.builders.SearchFilterRequestDtoBuilder.aPropertyFilter;
import static org.assertj.core.api.Assertions.assertThat;

/**
 * The repository support the inventory list operation (slice 3) will call: a deterministic name-ordered uuid page (uuid
 * tiebreak appended by the repository), the distinct value lists behind the searchable fields, and the list-row
 * projection.
 *
 * <p>
 * {@link #pagingOrdersByNameThenUuidAndPagesDeterministically} predicts Postgres's own {@code uuid} ordering with
 * {@link #sortedByUuidString}, not {@link UUID#compareTo} -- see that helper's javadoc for why.
 */
class CryptoAssetListQueryITest extends BaseSpringBootTest {

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

    /**
     * Three same-named rows, not two: with only two tied rows, a broken tiebreak still has a coin-flip chance of
     * incidentally returning them in ascending-uuid order, so the assertion below would only catch the regression about
     * half the time. With three, only 1 of the 3! = 6 possible orderings among the ties matches what is asserted, so a
     * dropped or misapplied tiebreak is caught 5 times out of 6.
     */
    @Test
    void pagingOrdersByNameThenUuidAndPagesDeterministically() {
        UUID aesA = upsert(new CryptoAssetIdentityFields(CryptographicAssetType.ALGORITHM, "AES", "oid-aes-a", null,
                null, null, null, null, null, null), null);
        UUID aesB = upsert(new CryptoAssetIdentityFields(CryptographicAssetType.ALGORITHM, "  aes  ", "oid-aes-b", null,
                null, null, null, null, null, null), null);
        UUID aesC = upsert(new CryptoAssetIdentityFields(CryptographicAssetType.ALGORITHM, "aes", "oid-aes-c", null,
                null, null, null, null, null, null), null);
        UUID ecdsa = upsert(new CryptoAssetIdentityFields(CryptographicAssetType.ALGORITHM, "ECDSA", "oid-ecdsa", null,
                null, null, null, null, null, null), null);
        UUID nullNamed = upsert(new CryptoAssetIdentityFields(CryptographicAssetType.CERTIFICATE, null, "oid-null-name",
                null, null, null, null, null, null, null), null);

        List<UUID> aesByUuidAscending = sortedByUuidString(aesA, aesB, aesC);
        UUID aesFirst = aesByUuidAscending.get(0);
        UUID aesSecond = aesByUuidAscending.get(1);
        UUID aesThird = aesByUuidAscending.get(2);

        List<UUID> all = assetRepository
                .findUuidsUsingSecurityFilter(SecurityFilter.create(), null, PageRequest.of(0, 10), nameAscending());
        assertThat(all)
                .describedAs("all three aes rows first (tiebroken by uuid ascending), then ecdsa, then the null name "
                        + "last")
                .containsExactly(aesFirst, aesSecond, aesThird, ecdsa, nullNamed);

        List<UUID> page0 = assetRepository
                .findUuidsUsingSecurityFilter(SecurityFilter.create(), null, PageRequest.of(0, 2), nameAscending());
        List<UUID> page1 = assetRepository
                .findUuidsUsingSecurityFilter(SecurityFilter.create(), null, PageRequest.of(1, 2), nameAscending());
        List<UUID> page2 = assetRepository
                .findUuidsUsingSecurityFilter(SecurityFilter.create(), null, PageRequest.of(2, 2), nameAscending());
        assertThat(page0).describedAs("page 0 is the first two of the full order").containsExactly(aesFirst, aesSecond);
        assertThat(page1)
                .describedAs("page 1's boundary falls inside the tied 'aes' name group -- the tiebreak makes it "
                        + "deterministic")
                .containsExactly(aesThird, ecdsa);
        assertThat(page2).describedAs("page 2 is the null-name row, still last").containsExactly(nullNamed);
    }

    @Test
    void distinctValueQueriesReturnCanonicalSortedValuesWithoutNullsOrDuplicates() {
        upsert(new CryptoAssetIdentityFields(CryptographicAssetType.ALGORITHM, "rsa-signature", "oid-1", "rsa", null,
                null, "SECP256R1", null, null, null), null);
        upsert(new CryptoAssetIdentityFields(CryptographicAssetType.ALGORITHM, "rsa-signature-2", "oid-2", " RSA ",
                null, null, " secp256r1 ", null, null, null), null);
        upsert(new CryptoAssetIdentityFields(CryptographicAssetType.ALGORITHM, "ecdsa-signature", "oid-3", "ecdsa",
                null, null, "P-256", null, null, null), null);
        upsert(new CryptoAssetIdentityFields(CryptographicAssetType.CERTIFICATE, "bare", "oid-4", null, null, null,
                null, null, null, null), null);

        assertThat(assetRepository.findDistinctCurve())
                .describedAs(
                        "distinct stored normalized values, sorted, no null; class folding (p-256 = secp256r1) is core#2072 ingest scope, not this query's")
                .containsExactly("p-256", "secp256r1");
        assertThat(assetRepository.findDistinctAlgorithmFamily())
                .describedAs(
                        "distinct stored normalized values, sorted, no null; class folding (p-256 = secp256r1) is core#2072 ingest scope, not this query's")
                .containsExactly("ecdsa", "rsa");
    }

    @Test
    void listRowsProjectSourceCountAndSumOccurrenceCountPerAsset() {
        UUID sourced = upsert(new CryptoAssetIdentityFields(CryptographicAssetType.ALGORITHM, "AES", "oid-sourced",
                null, null, null, null, null, null, null), null);
        UUID sourceless = upsert(new CryptoAssetIdentityFields(CryptographicAssetType.ALGORITHM, "ECDSA",
                "oid-sourceless", null, null, null, null, null, null, null), null);
        UUID guarded = upsert(new CryptoAssetIdentityFields(CryptographicAssetType.CERTIFICATE, "some-cn", null, null,
                null, null, null, null, null, null), CryptoAssetIdentityGuard.BARE_CN_SUBJECT);

        Cbom cbomOne = newCbom("urn:uuid:proj-one");
        Cbom cbomTwo = newCbom("urn:uuid:proj-two");
        sourceWriter
                .upsertSource(sourced, cbomOne.getUuid(), Map.of("k", "v"),
                        List.of(Map.of("location", "a"), Map.of("location", "b"), Map.of("location", "c")),
                        OffsetDateTime.now());
        sourceWriter
                .upsertSource(sourced, cbomTwo.getUuid(), Map.of("k", "v"),
                        List.of(Map.of("location", "d"), Map.of("location", "e")), OffsetDateTime.now());
        assetWriter.applyPqcVerdict(sourced, PqcVerdict.NOT_READY, "rule", "reason", 3, Map.of());

        List<CryptoAssetListRow> rows = assetRepository.findListRowsByUuids(List.of(sourced, sourceless, guarded));
        assertThat(rows).hasSize(3);

        CryptoAssetListRow sourcedRow = rowFor(rows, sourced);
        assertThat(sourcedRow.occurrenceCount())
                .describedAs("occurrences summed across both sources: 3 + 2")
                .isEqualTo(5);
        assertThat(sourcedRow.sourceCount()).describedAs("the writer's recompute maintains this").isEqualTo(2);
        assertThat(sourcedRow.pqcVerdict()).isEqualTo(PqcVerdict.NOT_READY);
        assertThat(sourcedRow.name()).isEqualTo("aes");
        assertThat(sourcedRow.oid())
                .describedAs("rides along as the nameless-row name fallback")
                .isEqualTo("oid-sourced");
        assertThat(sourcedRow.assetType()).isEqualTo(CryptographicAssetType.ALGORITHM);
        assertThat(sourcedRow.identityGuard()).isNull();

        CryptoAssetListRow sourcelessRow = rowFor(rows, sourceless);
        assertThat(sourcelessRow.occurrenceCount())
                .describedAs("no sources -- LEFT JOIN, not an inner join")
                .isEqualTo(0);
        assertThat(sourcelessRow.sourceCount()).isEqualTo(0);
        assertThat(sourcelessRow.pqcVerdict()).describedAs("never evaluated").isNull();

        CryptoAssetListRow guardedRow = rowFor(rows, guarded);
        assertThat(guardedRow.identityGuard()).isEqualTo(CryptoAssetIdentityGuard.BARE_CN_SUBJECT);
        assertThat(guardedRow.occurrenceCount()).isEqualTo(0);
        assertThat(guardedRow.sourceCount()).isEqualTo(0);
    }

    /**
     * The service's page loader tolerates a uuid whose row vanished between the page query and this projection -- this
     * is the repository half of that tolerance: an unknown uuid simply produces no row.
     */
    @Test
    void listRowProjectionSkipsAVanishedUuid() {
        UUID present = upsert(new CryptoAssetIdentityFields(CryptographicAssetType.ALGORITHM, "AES", "oid-present",
                null, null, null, null, null, null, null), null);

        List<CryptoAssetListRow> rows = assetRepository.findListRowsByUuids(List.of(present, UUID.randomUUID()));

        assertThat(rows).extracting(CryptoAssetListRow::uuid).containsExactly(present);
    }

    /**
     * The list endpoint counts with the plain (non-DISTINCT) variant, which is only correct while no predicate can
     * duplicate a root row. The source-CBOM EXISTS predicate is the shape that would do it as a join -- so this pins
     * the two counts equal through exactly that predicate, over an asset with two matching sources.
     */
    @Test
    void plainRowCountMatchesTheDistinctCountThroughTheSourceCbomPredicate() {
        UUID doubled = upsert(new CryptoAssetIdentityFields(CryptographicAssetType.ALGORITHM, "AES", "oid-doubled",
                null, null, null, null, null, null, null), null);
        Cbom one = newCbom("urn:uuid:count-one");
        Cbom two = newCbom("urn:uuid:count-two");
        sourceWriter.upsertSource(doubled, one.getUuid(), Map.of("k", "v"), List.of(), OffsetDateTime.now());
        sourceWriter.upsertSource(doubled, two.getUuid(), Map.of("k", "v"), List.of(), OffsetDateTime.now());

        SearchFilterRequestDto eitherSerial = aPropertyFilter(FilterField.CBOM_ASSET_SOURCE_CBOM,
                FilterConditionOperator.EQUALS, (Serializable) List.of("urn:uuid:count-one", "urn:uuid:count-two"));
        TriFunction<Root<CryptoAsset>, CriteriaBuilder, CriteriaQuery<?>, Predicate> where = (root, cb,
                cr) -> FilterPredicatesBuilder
                        .getFiltersPredicate(cb, cr, root, List.of(eitherSerial), UNRESTRICTED_ATTRIBUTE_CONTENT);

        assertThat(assetRepository.countRowsUsingSecurityFilter(SecurityFilter.create(), where))
                .isEqualTo(assetRepository.countUsingSecurityFilter(SecurityFilter.create(), where))
                .isEqualTo(1L);
    }

    // ---- helpers ----

    /**
     * The list operation's default order. The uuid tiebreak is not spelled here: SortOrderBuilder appends it to every
     * paged secured query, and this test exists to prove that appended tiebreak keeps the page boundaries stable.
     */
    private static BiFunction<Root<CryptoAsset>, CriteriaBuilder, Order> nameAscending() {
        return (r, cb) -> cb.asc(r.get("name"));
    }

    /**
     * The given UUIDs, ascending in Postgres's own {@code uuid} order. Postgres's comparator is an unsigned byte
     * compare over the 16 bytes ({@code uuid_cmp}, {@code memcmp}-based); {@link UUID#toString()} lexicographic order
     * matches it exactly, whereas {@link UUID#compareTo} does not -- it compares the two 64-bit halves as signed longs,
     * which disagrees with Postgres whenever the leading byte's sign bit differs between two UUIDs compared.
     */
    private static List<UUID> sortedByUuidString(UUID... uuids) {
        return Arrays.stream(uuids).sorted(Comparator.comparing(UUID::toString)).toList();
    }

    private static CryptoAssetListRow rowFor(List<CryptoAssetListRow> rows, UUID uuid) {
        return rows.stream().filter(r -> r.uuid().equals(uuid)).findFirst().orElseThrow();
    }

    private Cbom newCbom(String serialNumber) {
        return newCbom(serialNumber, 1);
    }

    private Cbom newCbom(String serialNumber, int version) {
        Cbom cbom = new Cbom();
        cbom.setSerialNumber(serialNumber);
        cbom.setVersion(version);
        cbom.setSpecVersion("1.7");
        return cbomRepository.save(cbom);
    }

    private UUID upsert(CryptoAssetIdentityFields fields, CryptoAssetIdentityGuard guard) {
        return assetWriter.upsertIdentity(AssetRowKeys.forFields(fields), fields, guard);
    }
}
