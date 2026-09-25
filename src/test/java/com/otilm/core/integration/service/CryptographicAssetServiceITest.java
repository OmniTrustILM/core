package com.otilm.core.integration.service;

import com.otilm.api.exception.NotFoundException;
import com.otilm.api.exception.ValidationException;
import com.otilm.api.model.client.certificate.SearchColumnRequestDto;
import com.otilm.api.model.client.certificate.SearchRequestDto;
import com.otilm.api.model.client.certificate.SearchSortRequestDto;
import com.otilm.api.model.common.NameAndUuidDto;
import com.otilm.api.model.common.PaginationResponseDto;
import com.otilm.api.model.core.cryptoasset.CryptographicAssetDto;
import com.otilm.api.model.core.cryptoasset.CryptographicAssetType;
import com.otilm.api.model.core.cryptoasset.PqcVerdict;
import com.otilm.api.model.core.search.FilterConditionOperator;
import com.otilm.api.model.core.search.FilterFieldSource;
import com.otilm.api.model.core.search.SortDirection;
import com.otilm.core.cbom.asset.AssetRowKeys;
import com.otilm.core.cbom.asset.CryptoAssetIdentityFields;
import com.otilm.core.dao.entity.Cbom;
import com.otilm.core.dao.repository.CbomRepository;
import com.otilm.core.enums.FilterField;
import com.otilm.core.model.cbom.CryptoAssetIdentityGuard;
import com.otilm.core.security.authz.SecuredUUID;
import com.otilm.core.security.authz.SecurityFilter;
import com.otilm.core.service.CryptographicAssetExternalService;
import com.otilm.core.service.ResourceExtensionService;
import com.otilm.core.service.writer.cbom.CryptoAssetSourceWriter;
import com.otilm.core.service.writer.cbom.CryptoAssetWriter;
import com.otilm.core.util.BaseSpringBootTest;
import java.time.OffsetDateTime;
import java.util.Arrays;
import java.util.Comparator;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;

import static com.otilm.core.util.builders.SearchFilterRequestDtoBuilder.aPropertyEqualsFilter;
import static com.otilm.core.util.builders.SearchFilterRequestDtoBuilder.aPropertyFilter;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * The list operation ({@link CryptographicAssetExternalService#listCryptographicAssets}) end to end, through the
 * service interface rather than the repository directly: ordering and paging determinism, the 1000-item clamp and
 * paging refusals, the list-row-to-DTO mapping, and the acceptance criteria from the issue itself -- filters that
 * answer across asset types, and a refuted OID that stays out of a default free-text search until the caller opts into
 * the facet.
 */
class CryptographicAssetServiceITest extends BaseSpringBootTest {

    @Autowired
    private CryptographicAssetExternalService cryptographicAssetService;

    @Autowired
    private CryptoAssetWriter assetWriter;

    @Autowired
    private CryptoAssetSourceWriter sourceWriter;

    @Autowired
    private CbomRepository cbomRepository;

    @Test
    void ordersByNameThenUuidAndPagesDeterministically() {
        UUID aesA = seedNamed(CryptographicAssetType.ALGORITHM, "AES", "oid-aes-a");
        UUID aesB = seedNamed(CryptographicAssetType.ALGORITHM, "  aes  ", "oid-aes-b");
        UUID ecdsa = seedNamed(CryptographicAssetType.ALGORITHM, "ECDSA", "oid-ecdsa");
        UUID nullNamed = seedNamed(CryptographicAssetType.CERTIFICATE, null, "oid-null-name");

        List<UUID> aesByUuidAscending = sortedByUuidString(aesA, aesB);
        UUID aesFirst = aesByUuidAscending.get(0);
        UUID aesSecond = aesByUuidAscending.get(1);

        PaginationResponseDto<CryptographicAssetDto> defaultPage = list(new SearchRequestDto());
        assertThat(defaultPage.getItems())
                .extracting(CryptographicAssetDto::getUuid)
                .containsExactly(aesFirst, aesSecond, ecdsa, nullNamed);
        assertThat(defaultPage.getPageNumber()).isEqualTo(1);
        assertThat(defaultPage.getItemsPerPage()).isEqualTo(10);
        assertThat(defaultPage.getTotalItems()).isEqualTo(4);
        assertThat(defaultPage.getTotalPages()).isEqualTo(1);

        SearchRequestDto firstOfTwo = new SearchRequestDto();
        firstOfTwo.setItemsPerPage(2);
        firstOfTwo.setPageNumber(1);
        PaginationResponseDto<CryptographicAssetDto> page1 = list(firstOfTwo);
        assertThat(page1.getItems()).extracting(CryptographicAssetDto::getUuid).containsExactly(aesFirst, aesSecond);
        assertThat(page1.getTotalPages()).isEqualTo(2);

        SearchRequestDto secondOfTwo = new SearchRequestDto();
        secondOfTwo.setItemsPerPage(2);
        secondOfTwo.setPageNumber(2);
        PaginationResponseDto<CryptographicAssetDto> page2 = list(secondOfTwo);
        assertThat(page2.getItems())
                .describedAs("page 1's boundary falls inside the tied 'aes' name group -- the uuid tiebreak makes "
                        + "it deterministic")
                .extracting(CryptographicAssetDto::getUuid)
                .containsExactly(ecdsa, nullNamed);
    }

    @Test
    void clampsOversizedPageAndRefusesInvalidPaging() {
        SearchRequestDto oversized = new SearchRequestDto();
        oversized.setItemsPerPage(5000);
        assertThat(list(oversized).getItemsPerPage()).isEqualTo(1000);

        SearchRequestDto zeroPage = new SearchRequestDto();
        zeroPage.setPageNumber(0);
        assertThatThrownBy(() -> list(zeroPage)).isInstanceOf(ValidationException.class);

        SearchRequestDto zeroItems = new SearchRequestDto();
        zeroItems.setItemsPerPage(0);
        assertThatThrownBy(() -> list(zeroItems)).isInstanceOf(ValidationException.class);

        // (pageNumber - 1) * itemsPerPage must fit an int: the JPA offset is an int, so an unchecked product either
        // throws deep in Hibernate (a 400, not the shaped 422) or -- worse -- wraps positive and silently serves the
        // wrong page while echoing the requested number.
        SearchRequestDto wrapping = new SearchRequestDto();
        wrapping.setPageNumber(4294969);
        wrapping.setItemsPerPage(1000);
        assertThatThrownBy(() -> list(wrapping))
                .describedAs("offset 4,294,968,000 wraps to +704 -- must be refused, not served")
                .isInstanceOf(ValidationException.class);

        SearchRequestDto overflowing = new SearchRequestDto();
        overflowing.setPageNumber(2147485);
        overflowing.setItemsPerPage(1000);
        assertThatThrownBy(() -> list(overflowing)).isInstanceOf(ValidationException.class);
    }

    @Test
    void mapsListRowsToDtos() {
        UUID sourced = seedNamed(CryptographicAssetType.ALGORITHM, "AES", "oid-sourced");
        Cbom cbomOne = newCbom("urn:uuid:svc-one");
        Cbom cbomTwo = newCbom("urn:uuid:svc-two");
        sourceWriter
                .upsertSource(sourced, cbomOne.getUuid(), Map.of("k", "v"),
                        List.of(Map.of("location", "a"), Map.of("location", "b"), Map.of("location", "c")),
                        OffsetDateTime.now());
        sourceWriter
                .upsertSource(sourced, cbomTwo.getUuid(), Map.of("k", "v"),
                        List.of(Map.of("location", "d"), Map.of("location", "e")), OffsetDateTime.now());
        assetWriter.applyPqcVerdict(sourced, PqcVerdict.NOT_READY, "rule", "reason", 3, Map.of());

        UUID guarded = upsert(new CryptoAssetIdentityFields(CryptographicAssetType.CERTIFICATE, "some-cn", null, null,
                null, null, null, null, null, null), CryptoAssetIdentityGuard.BARE_CN_SUBJECT);
        UUID contradicted = upsert(new CryptoAssetIdentityFields(CryptographicAssetType.CERTIFICATE,
                "contradicted-cert", null, null, null, null, null, null, null, null),
                CryptoAssetIdentityGuard.REFUTED_CERTIFICATE_DIGEST);

        UUID neverEvaluated = seedNamed(CryptographicAssetType.ALGORITHM, "RSA", "oid-never-evaluated");

        PaginationResponseDto<CryptographicAssetDto> page = list(new SearchRequestDto());

        CryptographicAssetDto sourcedDto = dtoFor(page, sourced);
        assertThat(sourcedDto.getSourceCbomCount()).isEqualTo(2);
        assertThat(sourcedDto.getOccurrenceCount())
                .describedAs("occurrences summed across both sources: 3 + 2")
                .isEqualTo(5);
        assertThat(sourcedDto.getPqcVerdict()).isEqualTo(PqcVerdict.NOT_READY);
        assertThat(sourcedDto.isQuarantined()).isFalse();
        assertThat(sourcedDto.getName()).describedAs("canonical spelling, not the seeded case").isEqualTo("aes");
        assertThat(sourcedDto.getUuid()).isEqualTo(sourced);

        CryptographicAssetDto guardedDto = dtoFor(page, guarded);
        assertThat(guardedDto.isQuarantined())
                .describedAs("BARE_CN_SUBJECT is a permanent DN-scope split with no reconciliation path -- not the "
                        + "contract's 'contradicting claims quarantined pending reconciliation'")
                .isFalse();

        CryptographicAssetDto contradictedDto = dtoFor(page, contradicted);
        assertThat(contradictedDto.isQuarantined())
                .describedAs("REFUTED_CERTIFICATE_DIGEST is the one guard the contract sentence describes: "
                        + "contradicting claims, pending reconciliation")
                .isTrue();

        CryptographicAssetDto neverEvaluatedDto = dtoFor(page, neverEvaluated);
        assertThat(neverEvaluatedDto.getPqcVerdict())
                .describedAs("never evaluated -> UNKNOWN, not null")
                .isEqualTo(PqcVerdict.UNKNOWN);
    }

    /**
     * The contract orders rows "by name ascending", and the only name it defines is the served display field -- for a
     * nameless row, its OID fallback. Sorting the bare column instead would put every nameless row last (NULL sorts
     * last under ASC), serving ["zzz-cipher", "0.aaa"]: descending on the wire.
     */
    @Test
    void ordersByTheServedNameNotTheBareColumn() {
        UUID named = seedNamed(CryptographicAssetType.ALGORITHM, "zzz-cipher", "9.9.9");
        UUID oidServed = seedNamed(CryptographicAssetType.CERTIFICATE, null, "0.aaa");

        PaginationResponseDto<CryptographicAssetDto> page = list(new SearchRequestDto());
        assertThat(page.getItems()).extracting(CryptographicAssetDto::getUuid).containsExactly(oidServed, named);
        assertThat(page.getItems()).extracting(CryptographicAssetDto::getName).containsExactly("0.aaa", "zzz-cipher");
    }

    @Test
    void sortsByNameOnTheServedLabelInBothDirections() {
        UUID bravo = seedNamed(CryptographicAssetType.ALGORITHM, "bravo", "5.5.5");
        UUID oidOnly = seedNamed(CryptographicAssetType.CERTIFICATE, null, "0.aaa");
        UUID zulu = seedNamed(CryptographicAssetType.ALGORITHM, "zulu", "1.1.1");
        UUID unlabelled = upsert(new CryptoAssetIdentityFields(CryptographicAssetType.ALGORITHM, null, "0.0.1",
                "ml-kem", null, null, null, null, null, null), CryptoAssetIdentityGuard.REFUTED_OID);

        assertThat(list(sortedBy(FilterField.CBOM_ASSET_NAME, SortDirection.ASC)).getItems())
                .extracting(CryptographicAssetDto::getUuid)
                .containsExactly(oidOnly, bravo, zulu, unlabelled);
        assertThat(list(sortedBy(FilterField.CBOM_ASSET_NAME, SortDirection.DESC)).getItems())
                .extracting(CryptographicAssetDto::getUuid)
                .describedAs("a row with no label to show stays last when the order is reversed")
                .containsExactly(zulu, bravo, oidOnly, unlabelled);
    }

    @Test
    void sortsByTypeAndByPqcVerdict() {
        UUID protocol = seedNamed(CryptographicAssetType.PROTOCOL, "alpha", "1.0.1");
        UUID algorithm = seedNamed(CryptographicAssetType.ALGORITHM, "bravo", "1.0.2");
        UUID certificate = seedNamed(CryptographicAssetType.CERTIFICATE, "charlie", "1.0.3");
        assetWriter.applyPqcVerdict(protocol, PqcVerdict.NOT_READY, "rule", "reason", 3, Map.of());
        assetWriter.applyPqcVerdict(algorithm, PqcVerdict.READY, "rule", "reason", 3, Map.of());
        assetWriter.applyPqcVerdict(certificate, PqcVerdict.NOT_APPLICABLE, "rule", "reason", 3, Map.of());

        assertThat(list(sortedBy(FilterField.CBOM_ASSET_TYPE, SortDirection.ASC)).getItems())
                .extracting(CryptographicAssetDto::getUuid)
                .containsExactly(algorithm, certificate, protocol);
        assertThat(list(sortedBy(FilterField.CBOM_ASSET_PQC_VERDICT, SortDirection.DESC)).getItems())
                .extracting(CryptographicAssetDto::getUuid)
                .containsExactly(algorithm, protocol, certificate);
    }

    @Test
    void theNextPageContinuesTheRequestedOrder() {
        UUID alpha = seedNamed(CryptographicAssetType.ALGORITHM, "alpha", "2.0.1");
        UUID bravo = seedNamed(CryptographicAssetType.ALGORITHM, "bravo", "2.0.2");
        UUID oidOnly = seedNamed(CryptographicAssetType.CERTIFICATE, null, "charlie-oid");
        UUID delta = seedNamed(CryptographicAssetType.ALGORITHM, "delta", "2.0.4");

        SearchRequestDto first = sortedBy(FilterField.CBOM_ASSET_NAME, SortDirection.DESC);
        first.setItemsPerPage(2);
        SearchRequestDto second = sortedBy(FilterField.CBOM_ASSET_NAME, SortDirection.DESC);
        second.setItemsPerPage(2);
        second.setPageNumber(2);

        assertThat(list(first).getItems()).extracting(CryptographicAssetDto::getUuid).containsExactly(delta, oidOnly);
        assertThat(list(second).getItems()).extracting(CryptographicAssetDto::getUuid).containsExactly(bravo, alpha);
    }

    @Test
    void refusesASortOnAFieldTheListingDoesNotShow() {
        seedNamed(CryptographicAssetType.ALGORITHM, "alpha", "3.0.1");

        SearchRequestDto request = sortedBy(FilterField.CBOM_ASSET_OID, SortDirection.ASC);
        assertThatThrownBy(() -> list(request))
                .isInstanceOf(ValidationException.class)
                .hasMessageContaining("cannot be used to order this listing");
    }

    @Test
    void requestingPropertyColumnsServesTheRowsWithoutAttributeValues() {
        UUID alpha = seedNamed(CryptographicAssetType.ALGORITHM, "alpha", "4.0.1");

        SearchRequestDto request = new SearchRequestDto();
        request
                .setColumns(List
                        .of(new SearchColumnRequestDto(FilterFieldSource.PROPERTY,
                                FilterField.CBOM_ASSET_PQC_VERDICT.name())));

        CryptographicAssetDto dto = dtoFor(list(request), alpha);
        assertThat(dto.getName()).isEqualTo("alpha");
        assertThat(dto.getAttributeValues()).isNull();
    }

    /**
     * A refuted OID must not be served as the display name: the contract's principle for refuted identifiers (stated on
     * the detail contract's per-OID flag) is that a client labels them instead of presenting them as fact, and the list
     * DTO carries no such flag. The row serves no name at all -- the interfaces-owned both-null residual -- and sorts
     * with the nameless rows, consistently with the search that refuses to match the same string.
     */
    @Test
    void aRefutedOidIsNotServedAsTheName() {
        UUID refutedNameless = upsert(new CryptoAssetIdentityFields(CryptographicAssetType.ALGORITHM, null, "0.0.1",
                "ml-kem", null, null, null, null, null, null), CryptoAssetIdentityGuard.REFUTED_OID);
        UUID named = seedNamed(CryptographicAssetType.ALGORITHM, "aes", "1.2.3");

        PaginationResponseDto<CryptographicAssetDto> page = list(new SearchRequestDto());
        assertThat(dtoFor(page, refutedNameless).getName()).isNull();
        assertThat(page.getItems())
                .extracting(CryptographicAssetDto::getUuid)
                .describedAs("serves no name -> sorts after named rows even though '0.0.1' < 'aes'")
                .containsExactly(named, refutedNameless);
    }

    @Test
    void aRowWithNeitherNameNorOidServesNoName() {
        UUID bare = upsert(new CryptoAssetIdentityFields(CryptographicAssetType.CERTIFICATE, null, null, null, null,
                null, null, null, null, null), null);
        assertThat(dtoFor(list(new SearchRequestDto()), bare).getName())
                .describedAs("interfaces-owned residual: the REQUIRED name has no value to serve")
                .isNull();
    }

    /**
     * The issue's "normalized fields answer for every asset type" criterion: one filter value on a shared field returns
     * rows of different {@link CryptographicAssetType}s, and the reported total tracks the filtered count.
     */
    @Test
    void filtersNarrowResultsAcrossAssetTypes() {
        UUID algorithmRow = upsert(new CryptoAssetIdentityFields(CryptographicAssetType.ALGORITHM, "ECDSA", null,
                "ecdsa", "signature", "P-256", "secp256r1", null, null, null), null);
        UUID certificateRow = upsert(new CryptoAssetIdentityFields(CryptographicAssetType.CERTIFICATE, "some-cert",
                null, null, null, null, "secp256r1", null, null, null), null);
        seedNamed(CryptographicAssetType.ALGORITHM, "RSA", "oid-unrelated");

        SearchRequestDto request = new SearchRequestDto();
        request.setFilters(List.of(aPropertyEqualsFilter(FilterField.CBOM_ASSET_CURVE, "secp256r1")));
        PaginationResponseDto<CryptographicAssetDto> page = list(request);

        assertThat(page.getItems())
                .extracting(CryptographicAssetDto::getUuid)
                .containsExactlyInAnyOrder(algorithmRow, certificateRow);
        assertThat(page.getTotalItems()).describedAs("the filtered count, not the whole table").isEqualTo(2);
    }

    /**
     * The issue's own acceptance criterion, end to end through the service: a refuted OID must never let a default
     * free-text search surface the row, but opting into the refuted-OID facet lets it answer again.
     */
    @Test
    void freeTextRefusesARefutedOidUntilTheRefutedFacetOptsIn() {
        UUID refuted = upsert(new CryptoAssetIdentityFields(CryptographicAssetType.ALGORITHM, "ML-KEM-768",
                "2.16.840.1.101.3.4.4.2", "ml-kem", "kem", null, null, null, null, null),
                CryptoAssetIdentityGuard.REFUTED_OID);

        SearchRequestDto freeTextOnly = new SearchRequestDto();
        freeTextOnly
                .setFilters(List
                        .of(aPropertyFilter(FilterField.CBOM_ASSET_FREE_TEXT, FilterConditionOperator.CONTAINS,
                                "101.3.4.4")));
        PaginationResponseDto<CryptographicAssetDto> withoutOptIn = list(freeTextOnly);
        assertThat(withoutOptIn.getItems()).isEmpty();
        assertThat(withoutOptIn.getTotalItems()).isZero();

        SearchRequestDto withOptIn = new SearchRequestDto();
        withOptIn
                .setFilters(List
                        .of(aPropertyFilter(FilterField.CBOM_ASSET_FREE_TEXT, FilterConditionOperator.CONTAINS,
                                "101.3.4.4"), aPropertyEqualsFilter(FilterField.CBOM_ASSET_OID_REFUTED, "true")));
        PaginationResponseDto<CryptographicAssetDto> withOptInResult = list(withOptIn);
        assertThat(withOptInResult.getItems()).extracting(CryptographicAssetDto::getUuid).containsExactly(refuted);
        assertThat(withOptInResult.getItems().getFirst().isQuarantined())
                .describedAs("REFUTED_OID is one component contradicting itself, not 'sources making contradicting "
                        + "claims pending reconciliation' -- served unflagged")
                .isFalse();
    }

    /**
     * The contract marks {@code name} REQUIRED and the wire mapper drops nulls, so a row that has no producer name must
     * serve its next-best stable label -- the recorded OID, the same fallback the object picker's display label uses. A
     * row with neither name nor OID remains a documented contract friction for interfaces to settle.
     */
    @Test
    void aNamelessRowServesItsOidAsTheRequiredName() {
        UUID nameless = upsert(new CryptoAssetIdentityFields(CryptographicAssetType.CERTIFICATE, null, "oid-only-row",
                null, null, null, null, null, null, null), null);

        CryptographicAssetDto dto = dtoFor(list(new SearchRequestDto()), nameless);
        assertThat(dto.getName()).isEqualTo("oid-only-row");
    }

    @Test
    void totalPagesReflectsFilteredCountAcrossPages() {
        seedFamily("AES-1", "aes");
        seedFamily("AES-2", "aes");
        seedFamily("AES-3", "aes");
        seedFamily("RSA-1", "rsa");

        SearchRequestDto request = new SearchRequestDto();
        request.setItemsPerPage(2);
        request.setPageNumber(1);
        request.setFilters(List.of(aPropertyEqualsFilter(FilterField.CBOM_ASSET_ALGORITHM_FAMILY, "aes")));
        PaginationResponseDto<CryptographicAssetDto> page1 = list(request);
        assertThat(page1.getItems()).hasSize(2);
        assertThat(page1.getTotalItems()).isEqualTo(3);
        assertThat(page1.getTotalPages()).isEqualTo(2);

        request.setPageNumber(2);
        PaginationResponseDto<CryptographicAssetDto> page2 = list(request);
        assertThat(page2.getItems()).hasSize(1);
        assertThat(page2.getTotalItems()).isEqualTo(3);
    }

    // ---- the auth service's per-object listing (ResourceExtensionService) ----

    @Test
    void listResourceObjectsLabelsByNameOrFallsBackToOid() {
        UUID named = seedNamed(CryptographicAssetType.ALGORITHM, "AES", "oid-named");
        UUID bare = upsert(new CryptoAssetIdentityFields(CryptographicAssetType.CERTIFICATE, null, "oid-bare-only",
                null, null, null, null, null, null, null), null);

        UUID refutedNameless = upsert(new CryptoAssetIdentityFields(CryptographicAssetType.ALGORITHM, null,
                "oid-refuted-label", "ml-kem", null, null, null, null, null, null),
                CryptoAssetIdentityGuard.REFUTED_OID);

        List<NameAndUuidDto> objects = resourceExtension().listResourceObjects(SecurityFilter.create(), null, null);

        assertThat(nameFor(objects, named))
                .describedAs("a named row is labeled by its canonical name")
                .isEqualTo("aes");
        assertThat(nameFor(objects, bare))
                .describedAs("a name-less row falls back to its oid")
                .isEqualTo("oid-bare-only");
        assertThat(nameFor(objects, refutedNameless))
                .describedAs("a refuted OID is never presented as a label -- the picker shows no name rather than a "
                        + "value the refuted ruling calls a false fact")
                .isNull();
    }

    @Test
    void listResourceObjectsHonoursPickerFilters() {
        UUID aes = seedNamed(CryptographicAssetType.ALGORITHM, "AES", "oid-picker-aes");
        seedNamed(CryptographicAssetType.ALGORITHM, "RSA", "oid-picker-rsa");

        List<NameAndUuidDto> filtered = resourceExtension()
                .listResourceObjects(SecurityFilter.create(),
                        List.of(aPropertyEqualsFilter(FilterField.CBOM_ASSET_NAME, "aes")), null);

        assertThat(filtered)
                .describedAs("a search typed into the role editor's picker narrows the objects, like the "
                        + "entity-instance precedent")
                .extracting(NameAndUuidDto::getUuid)
                .containsExactly(aes.toString());
    }

    @Test
    void getResourceObjectInternalReturnsNameAndUuidOrThrowsNotFound() throws NotFoundException {
        UUID named = seedNamed(CryptographicAssetType.ALGORITHM, "AES", "oid-internal");

        NameAndUuidDto found = resourceExtension().getResourceObjectInternal(named);
        assertThat(found.getUuid()).isEqualTo(named.toString());
        assertThat(found.getName()).isEqualTo("aes");

        UUID missing = UUID.randomUUID();
        ResourceExtensionService extension = resourceExtension();
        assertThatThrownBy(() -> extension.getResourceObjectInternal(missing)).isInstanceOf(NotFoundException.class);
    }

    @Test
    void getResourceObjectExternalReturnsNameAndUuidOrThrowsNotFound() throws NotFoundException {
        UUID named = seedNamed(CryptographicAssetType.ALGORITHM, "AES", "oid-external");

        NameAndUuidDto found = resourceExtension().getResourceObjectExternal(SecuredUUID.fromUUID(named));
        assertThat(found.getUuid()).isEqualTo(named.toString());
        assertThat(found.getName()).isEqualTo("aes");

        UUID missing = UUID.randomUUID();
        SecuredUUID missingUuid = SecuredUUID.fromUUID(missing);
        ResourceExtensionService extension = resourceExtension();
        assertThatThrownBy(() -> extension.getResourceObjectExternal(missingUuid))
                .isInstanceOf(NotFoundException.class);
    }

    @Test
    void evaluatePermissionChainThrowsNotFoundForAMissingUuidAndPassesForAnExistingOne() throws NotFoundException {
        UUID existing = seedNamed(CryptographicAssetType.ALGORITHM, "AES", "oid-chain");
        resourceExtension().evaluatePermissionChain(SecuredUUID.fromUUID(existing));

        UUID missing = UUID.randomUUID();
        SecuredUUID missingUuid = SecuredUUID.fromUUID(missing);
        ResourceExtensionService extension = resourceExtension();
        assertThatThrownBy(() -> extension.evaluatePermissionChain(missingUuid)).isInstanceOf(NotFoundException.class);
    }

    // ---- helpers ----

    private PaginationResponseDto<CryptographicAssetDto> list(SearchRequestDto request) {
        return cryptographicAssetService.listCryptographicAssets(SecurityFilter.create(), request);
    }

    private static SearchRequestDto sortedBy(FilterField field, SortDirection direction) {
        SearchRequestDto request = new SearchRequestDto();
        request.setSort(new SearchSortRequestDto(FilterFieldSource.PROPERTY, field.name(), direction));
        return request;
    }

    private UUID seedNamed(CryptographicAssetType type, String name, String oid) {
        return upsert(new CryptoAssetIdentityFields(type, name, oid, null, null, null, null, null, null, null), null);
    }

    private UUID seedFamily(String name, String family) {
        return upsert(new CryptoAssetIdentityFields(CryptographicAssetType.ALGORITHM, name, null, family, null, null,
                null, null, null, null), null);
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

    private static CryptographicAssetDto dtoFor(PaginationResponseDto<CryptographicAssetDto> page, UUID uuid) {
        return page.getItems().stream().filter(dto -> dto.getUuid().equals(uuid)).findFirst().orElseThrow();
    }

    // CryptographicAssetServiceImpl implements both CryptographicAssetExternalService and ResourceExtensionService
    // on the one bean; casting the already-autowired proxy reaches the same instance under the second interface.
    private ResourceExtensionService resourceExtension() {
        return (ResourceExtensionService) cryptographicAssetService;
    }

    private static String nameFor(List<NameAndUuidDto> objects, UUID uuid) {
        return objects
                .stream()
                .filter(object -> object.getUuid().equals(uuid.toString()))
                .findFirst()
                .orElseThrow()
                .getName();
    }

    /**
     * The given UUIDs, ascending in Postgres's own {@code uuid} order -- see
     * {@code CryptoAssetListQueryITest#sortedByUuidString} for why {@link UUID#toString()} order, not
     * {@link UUID#compareTo}, is what Postgres actually applies.
     */
    private static List<UUID> sortedByUuidString(UUID... uuids) {
        return Arrays.stream(uuids).sorted(Comparator.comparing(UUID::toString)).toList();
    }
}
