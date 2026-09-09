package com.otilm.core.integration.service;

import com.otilm.api.model.client.certificate.SearchRequestDto;
import com.otilm.api.model.client.dashboard.CryptographicAssetStatisticsDto;
import com.otilm.api.model.common.PaginationResponseDto;
import com.otilm.api.model.core.auth.Resource;
import com.otilm.api.model.core.cryptoasset.CryptographicAssetDto;
import com.otilm.api.model.core.cryptoasset.CryptographicAssetType;
import com.otilm.api.model.core.cryptoasset.PqcVerdict;
import com.otilm.core.cbom.asset.AssetRowKeys;
import com.otilm.core.cbom.asset.CryptoAssetIdentityFields;
import com.otilm.core.dao.entity.Cbom;
import com.otilm.core.dao.repository.CbomRepository;
import com.otilm.core.model.auth.ResourceAction;
import com.otilm.core.model.cbom.CryptoAssetIdentityGuard;
import com.otilm.core.security.authz.SecurityFilter;
import com.otilm.core.security.authz.opa.dto.OpaObjectAccessResult;
import com.otilm.core.service.CryptographicAssetExternalService;
import com.otilm.core.service.writer.cbom.CbomAssetSyncStateWriter;
import com.otilm.core.service.writer.cbom.CryptoAssetSourceWriter;
import com.otilm.core.service.writer.cbom.CryptoAssetWriter;
import com.otilm.core.util.BaseSpringBootTest;
import java.time.OffsetDateTime;
import java.time.ZoneOffset;
import java.time.temporal.ChronoUnit;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;
import org.springframework.beans.factory.annotation.Autowired;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.Mockito.when;

/**
 * The statistics operation ({@link CryptographicAssetExternalService#getCryptographicAssetStatistics}) end to end,
 * through the service interface: densify-and-fold over real rows, the core#2145 acceptance criteria that the badges
 * reconcile with the list under identical permission filtering and that the completeness block reflects partial sync,
 * the top-N family cutoff, and the independence of the two security gates -- CRYPTO_ASSET for the inventory badges,
 * CBOM for the completeness block.
 *
 * <p>
 * Deliberately not {@code @Transactional}: {@link CbomAssetSyncStateWriter} and the crypto-asset writers commit their
 * own transactions, and the statistics query fans out across virtual threads that must see those commits rather than an
 * uncommitted outer transaction visible only to this thread.
 */
class CryptographicAssetStatisticsITest extends BaseSpringBootTest {

    @Autowired
    private CryptographicAssetExternalService cryptographicAssetService;

    @Autowired
    private CryptoAssetWriter assetWriter;

    @Autowired
    private CryptoAssetSourceWriter sourceWriter;

    @Autowired
    private CbomRepository cbomRepository;

    @Autowired
    private CbomAssetSyncStateWriter syncStateWriter;

    @Test
    void countsDensifyAndFoldExactlyAsServed() {
        // 2 algorithms (one NOT_READY verdict, one never evaluated), 1 certificate with a family, 1 protocol without
        UUID a1 = seedTyped(CryptographicAssetType.ALGORITHM, "RSA-2048");
        seedTyped(CryptographicAssetType.ALGORITHM, "AES-128");
        seedTypedWithFamily(CryptographicAssetType.CERTIFICATE, "leaf", "RSA");
        seedTyped(CryptographicAssetType.PROTOCOL, "TLS-1.3");
        applyVerdict(a1, PqcVerdict.NOT_READY);

        CryptographicAssetStatisticsDto dto = cryptographicAssetService
                .getCryptographicAssetStatistics(SecurityFilter.create());

        assertEquals(4L, dto.getTotalAssets());
        assertEquals(2L, dto.getStatByType().get("algorithm"));
        assertEquals(1L, dto.getStatByType().get("certificate"));
        assertEquals(0L, dto.getStatByType().get("unroutable")); // densified
        assertEquals(1L, dto.getStatByPqcVerdict().get("notReady"));
        assertEquals(3L, dto.getStatByPqcVerdict().get("unknown")); // NULL verdicts fold into unknown
        // algorithmFamily is producer text and folds like every other identity field, so "RSA" is stored/served as
        // "rsa" -- see CryptoAssetIdentityFields#normalized.
        assertEquals(1L, dto.getStatByAlgorithmFamily().get("rsa"));
        assertEquals(1L, dto.getDistinctAlgorithmFamilyCount());
        assertEquals(3L, dto.getUnassignedAssetCount());
    }

    /**
     * The core#2145 AC: the badges reconcile with the list under identical permission filtering, both unrestricted and
     * with a subset of the inventory forbidden by OPA.
     */
    @Test
    void statisticsReconcileWithTheListUnderIdenticalPermissionFiltering() {
        UUID a1 = seedTyped(CryptographicAssetType.ALGORITHM, "alg-1");
        UUID a2 = seedTyped(CryptographicAssetType.ALGORITHM, "alg-2");
        UUID a3 = seedTyped(CryptographicAssetType.CERTIFICATE, "cert-1");
        UUID a4 = seedTyped(CryptographicAssetType.CERTIFICATE, "cert-2");
        seedTyped(CryptographicAssetType.PROTOCOL, "proto-1");
        applyVerdict(a1, PqcVerdict.READY);
        applyVerdict(a3, PqcVerdict.NOT_READY);

        assertStatisticsReconcileWithTheList(5);

        // Forbid a subset (2 of the 5 seeded assets); calling the list service method here goes through the same
        // @ExternalAuthorization with a fresh SecurityFilter.create(), so the OPA mock applies the identical
        // restriction to both reads -- which is the point of the assertion.
        forbidCryptoAssetObjects(List.of(a2, a4));
        assertStatisticsReconcileWithTheList(3);
    }

    /**
     * The core#2145 AC: the completeness block reflects a partially-synced inventory, and its timestamp advances as
     * later syncs complete.
     */
    @Test
    void completenessBlockIsCorrectUnderPartialSync() {
        Cbom a = newCbom("urn:uuid:completeness-a");
        Cbom b = newCbom("urn:uuid:completeness-b");
        Cbom c = newCbom("urn:uuid:completeness-c");
        Cbom d = newCbom("urn:uuid:completeness-d");
        // a is left PENDING (the entity default)
        syncStateWriter.markInProgress(b.getUuid());
        OffsetDateTime t1 = OffsetDateTime.now(ZoneOffset.UTC).truncatedTo(ChronoUnit.MICROS);
        syncStateWriter.markSynced(c.getUuid(), t1);
        syncStateWriter.markFailed(d.getUuid(), "boom");
        UUID contributor = seedTyped(CryptographicAssetType.ALGORITHM, "contributor");
        sourceWriter
                .upsertSource(contributor, c.getUuid(), Map.of("name", "contributor"),
                        List.of(Map.of("location", "a.c")), OffsetDateTime.now());

        CryptographicAssetStatisticsDto dto = cryptographicAssetService
                .getCryptographicAssetStatistics(SecurityFilter.create());

        Map<String, Long> bySyncState = dto.getSyncCompleteness().getCbomStatBySyncState();
        assertThat(bySyncState.get("pending")).isEqualTo(1L);
        assertThat(bySyncState.get("inProgress")).isEqualTo(1L);
        assertThat(bySyncState.get("synced")).isEqualTo(1L);
        assertThat(bySyncState.get("failed")).isEqualTo(1L);
        assertThat(dto.getSyncCompleteness().getLastCompletedSyncAt()).isEqualTo(t1);
        assertThat(dto.getSourceCbomCount())
                .describedAs("only c has a source row, so only c contributed")
                .isEqualTo(1L);

        OffsetDateTime t2later = t1.plusSeconds(30);
        syncStateWriter.markSynced(d.getUuid(), t2later);
        CryptographicAssetStatisticsDto after = cryptographicAssetService
                .getCryptographicAssetStatistics(SecurityFilter.create());
        assertThat(after.getSyncCompleteness().getLastCompletedSyncAt()).isEqualTo(t2later);
    }

    @Test
    void sourceCbomCountCountsContributingDocumentsOnce() {
        UUID assetA = seedTyped(CryptographicAssetType.ALGORITHM, "source-count-a");
        UUID assetB = seedTyped(CryptographicAssetType.ALGORITHM, "source-count-b");
        Cbom contributing = newCbom("urn:uuid:source-count-contributing");
        newCbom("urn:uuid:source-count-untouched"); // no source rows -- must count zero
        sourceWriter
                .upsertSource(assetA, contributing.getUuid(), Map.of("name", "source-count-a"),
                        List.of(Map.of("location", "a.c")), OffsetDateTime.now());
        sourceWriter
                .upsertSource(assetB, contributing.getUuid(), Map.of("name", "source-count-b"),
                        List.of(Map.of("location", "b.c")), OffsetDateTime.now());

        CryptographicAssetStatisticsDto dto = cryptographicAssetService
                .getCryptographicAssetStatistics(SecurityFilter.create());

        assertThat(dto.getSourceCbomCount())
                .describedAs("one cbom sourcing two assets counts once; the untouched cbom counts zero")
                .isEqualTo(1L);
    }

    @Test
    void emptyInventoryServesZeroesNotNulls() {
        CryptographicAssetStatisticsDto dto = cryptographicAssetService
                .getCryptographicAssetStatistics(SecurityFilter.create());

        assertThat(dto.getTotalAssets()).isZero();
        assertThat(dto.getStatByType()).hasSize(5);
        assertThat(dto.getStatByType().values()).containsOnly(0L);
        assertThat(dto.getStatByPqcVerdict()).hasSize(4);
        assertThat(dto.getStatByPqcVerdict().values()).containsOnly(0L);
        assertThat(dto.getUnassignedAssetCount()).isZero();
        assertThat(dto.getDistinctAlgorithmFamilyCount()).isZero();
        assertThat(dto.getStatByAlgorithmFamily()).isEmpty();
        assertThat(dto.getSourceCbomCount()).isZero();
        assertThat(dto.getSyncCompleteness().getCbomStatBySyncState()).hasSize(4);
        assertThat(dto.getSyncCompleteness().getCbomStatBySyncState().values()).containsOnly(0L);
        assertThat(dto.getSyncCompleteness().getLastCompletedSyncAt()).isNull();
    }

    @Test
    void familyTopNAndOverflowOverRealRows() {
        for (int i = 1; i <= 12; i++) {
            seedTypedWithFamily(CryptographicAssetType.ALGORITHM, "family-top-n-" + i, "family-" + i);
        }

        CryptographicAssetStatisticsDto dto = cryptographicAssetService
                .getCryptographicAssetStatistics(SecurityFilter.create());

        assertThat(dto.getStatByAlgorithmFamily()).hasSize(10);
        assertThat(dto.getDistinctAlgorithmFamilyCount()).isEqualTo(12L);
    }

    /**
     * The two security gates are independent: CRYPTO_ASSET scopes the inventory badges, CBOM scopes the completeness
     * block, and forbidding one must not perturb the other. F2: a CBOM access denial that is total is a
     * permission-shaped zero, not a fact about the estate, so the document-derived fields are omitted entirely rather
     * than served as zeroes that read as "nothing has ever synced".
     */
    @Test
    void cbomDenialOmitsTheCompletenessBlock() {
        UUID asset1 = seedTyped(CryptographicAssetType.ALGORITHM, "cbom-restricted-1");
        seedTyped(CryptographicAssetType.CERTIFICATE, "cbom-restricted-2");
        Cbom cbom = newCbom("urn:uuid:cbom-restricted");
        syncStateWriter.markSynced(cbom.getUuid(), OffsetDateTime.now(ZoneOffset.UTC).truncatedTo(ChronoUnit.MICROS));
        sourceWriter
                .upsertSource(asset1, cbom.getUuid(), Map.of("name", "cbom-restricted-1"),
                        List.of(Map.of("location", "a.c")), OffsetDateTime.now());

        denyObjectAccess(Resource.CBOM, ResourceAction.LIST);

        CryptographicAssetStatisticsDto dto = cryptographicAssetService
                .getCryptographicAssetStatistics(SecurityFilter.create());

        assertThat(dto.getSourceCbomCount())
                .describedAs("a permission-shaped zero would read as a never-synced estate; omit instead")
                .isNull();
        assertThat(dto.getSyncCompleteness()).isNull();
        assertThat(dto.getTotalAssets())
                .describedAs("asset scope is CRYPTO_ASSET, document scope is CBOM -- the two gates are independent")
                .isEqualTo(2L);
    }

    /**
     * F2's partial-restriction twin: a caller who can see one of two cboms still gets the scoped counts, not the
     * omission -- omission is reserved for a total denial.
     */
    @Test
    void partialCbomRestrictionStillServesScopedCounts() {
        UUID asset1 = seedTyped(CryptographicAssetType.ALGORITHM, "cbom-partial-1");
        Cbom visible = newCbom("urn:uuid:cbom-partial-visible");
        Cbom hidden = newCbom("urn:uuid:cbom-partial-hidden");
        OffsetDateTime syncedAt = OffsetDateTime.now(ZoneOffset.UTC).truncatedTo(ChronoUnit.MICROS);
        syncStateWriter.markSynced(visible.getUuid(), syncedAt);
        syncStateWriter.markSynced(hidden.getUuid(), syncedAt);
        sourceWriter
                .upsertSource(asset1, visible.getUuid(), Map.of("name", "cbom-partial-1"),
                        List.of(Map.of("location", "a.c")), OffsetDateTime.now());

        forbidCbomObjects(List.of(hidden.getUuid()));

        CryptographicAssetStatisticsDto dto = cryptographicAssetService
                .getCryptographicAssetStatistics(SecurityFilter.create());

        assertThat(dto.getSourceCbomCount())
                .describedAs("only the visible cbom is counted; a partial restriction is not deniesEverything")
                .isEqualTo(1L);
        assertThat(dto.getSyncCompleteness()).isNotNull();
        assertThat(
                dto.getSyncCompleteness().getCbomStatBySyncState().values().stream().mapToLong(Long::longValue).sum())
                .describedAs("only the visible cbom is in scope, even though both are synced")
                .isEqualTo(1L);
    }

    // ---- helpers ----

    private void assertStatisticsReconcileWithTheList(long expectedTotalAssets) {
        CryptographicAssetStatisticsDto dto = cryptographicAssetService
                .getCryptographicAssetStatistics(SecurityFilter.create());
        PaginationResponseDto<CryptographicAssetDto> page = cryptographicAssetService
                .listCryptographicAssets(SecurityFilter.create(), new SearchRequestDto());

        // The absolute count, not just the relational equalities below: if the OPA stub ever silently stopped
        // matching, both dto and page would agree on the (wrong) unrestricted total and every assertion here would
        // still pass.
        assertThat(dto.getTotalAssets()).isEqualTo(expectedTotalAssets);
        assertThat(dto.getTotalAssets()).isEqualTo(page.getTotalItems());
        assertThat(dto.getStatByType().values().stream().mapToLong(Long::longValue).sum())
                .isEqualTo(dto.getTotalAssets());
        assertThat(dto.getStatByPqcVerdict().values().stream().mapToLong(Long::longValue).sum())
                .isEqualTo(dto.getTotalAssets());
    }

    /**
     * Stubs the OPA object-access vote for {@code cryptoAssets:list} so every uuid in {@code forbidden} is denied while
     * the rest of the inventory stays allowed -- unlike {@link #denyObjectAccess} (denies everything) and
     * {@link #restrictObjectAccess} (allows only one unrelated random uuid), this leaves a real, known-size subset of
     * the seeded rows visible so the reconciliation assertion is meaningful under partial restriction.
     */
    private void forbidCryptoAssetObjects(List<UUID> forbidden) {
        OpaObjectAccessResult partial = new OpaObjectAccessResult();
        partial.setActionAllowedForGroupOfObjects(true);
        partial.setAllowedObjects(List.of());
        partial.setForbiddenObjects(forbidden.stream().map(UUID::toString).toList());
        when(opaClient
                .checkObjectAccess(Mockito.any(),
                        Mockito
                                .argThat(req -> req != null && req.getProperties() != null
                                        && Resource.CRYPTO_ASSET.getCode().equals(req.getProperties().get("name"))
                                        && ResourceAction.LIST.getCode().equals(req.getProperties().get("action"))),
                        Mockito.any(), Mockito.any()))
                .thenReturn(partial);
    }

    /**
     * The CBOM twin of {@link #forbidCryptoAssetObjects}: stubs the OPA object-access vote for {@code cboms:list} so
     * every uuid in {@code forbidden} is denied while the rest of the CBOM estate stays visible -- a PARTIAL
     * restriction, as opposed to {@link #denyObjectAccess} which denies the whole resource.
     */
    private void forbidCbomObjects(List<UUID> forbidden) {
        OpaObjectAccessResult partial = new OpaObjectAccessResult();
        partial.setActionAllowedForGroupOfObjects(true);
        partial.setAllowedObjects(List.of());
        partial.setForbiddenObjects(forbidden.stream().map(UUID::toString).toList());
        when(opaClient
                .checkObjectAccess(Mockito.any(),
                        Mockito
                                .argThat(req -> req != null && req.getProperties() != null
                                        && Resource.CBOM.getCode().equals(req.getProperties().get("name"))
                                        && ResourceAction.LIST.getCode().equals(req.getProperties().get("action"))),
                        Mockito.any(), Mockito.any()))
                .thenReturn(partial);
    }

    private UUID seedTyped(CryptographicAssetType type, String name) {
        return upsert(new CryptoAssetIdentityFields(type, name, null, null, null, null, null, null, null, null), null);
    }

    private UUID seedTypedWithFamily(CryptographicAssetType type, String name, String family) {
        return upsert(new CryptoAssetIdentityFields(type, name, null, family, null, null, null, null, null, null),
                null);
    }

    private void applyVerdict(UUID assetUuid, PqcVerdict verdict) {
        assetWriter.applyPqcVerdict(assetUuid, verdict, "rule", "reason", 1, Map.of());
    }

    private UUID upsert(CryptoAssetIdentityFields fields, CryptoAssetIdentityGuard guard) {
        return assetWriter.upsertIdentity(AssetRowKeys.forFields(fields), fields, guard);
    }

    private Cbom newCbom(String serialNumber) {
        Cbom cbom = new Cbom();
        cbom.setSerialNumber(serialNumber);
        cbom.setVersion(1);
        cbom.setSpecVersion("1.7");
        return cbomRepository.save(cbom);
    }
}
