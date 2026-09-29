package com.otilm.core.integration.service;

import com.fasterxml.jackson.databind.JsonNode;
import com.otilm.api.exception.NotFoundException;
import com.otilm.api.exception.ValidationException;
import com.otilm.api.model.client.certificate.SearchRequestDto;
import com.otilm.api.model.client.certificate.SearchSortRequestDto;
import com.otilm.api.model.common.PaginationResponseDto;
import com.otilm.api.model.core.auth.Resource;
import com.otilm.api.model.core.cbom.CbomContributedAssetDto;
import com.otilm.api.model.core.search.FilterFieldSource;
import com.otilm.api.model.core.search.SortDirection;
import com.otilm.core.cbom.ingest.CbomAssetIngestService;
import com.otilm.core.cbom.ingest.CbomIngestTestFixtures;
import com.otilm.core.cbom.sync.CbomSyncPolicy;
import com.otilm.core.dao.entity.Cbom;
import com.otilm.core.dao.entity.cbom.CryptoAsset;
import com.otilm.core.dao.repository.CbomRepository;
import com.otilm.core.dao.repository.cbom.CryptoAssetRepository;
import com.otilm.core.enums.FilterField;
import com.otilm.core.model.auth.ResourceAction;
import com.otilm.core.security.authz.SecuredUUID;
import com.otilm.core.security.authz.SecurityFilter;
import com.otilm.core.security.authz.opa.dto.OpaObjectAccessResult;
import com.otilm.core.service.CbomExternalService;
import com.otilm.core.util.BaseSpringBootTest;
import java.time.OffsetDateTime;
import java.util.List;
import java.util.UUID;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;
import org.springframework.beans.factory.annotation.Autowired;

import static com.otilm.core.util.builders.SearchFilterRequestDtoBuilder.aPropertyEqualsFilter;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.when;

/**
 * The assets one CBOM record contributed, read through the CBOM gate and the asset gate: what the page carries, which
 * document and which version it is scoped to, and what the caller's asset scope hides.
 */
class CbomContributedAssetsITest extends BaseSpringBootTest {

    private static final OffsetDateTime NOW = OffsetDateTime.parse("2026-09-29T10:00:00Z");

    private static final CbomSyncPolicy POLICY = CbomSyncPolicy.DEFAULTS;

    @Autowired
    private CbomExternalService cbomService;

    @Autowired
    private CbomAssetIngestService ingestService;

    @Autowired
    private CbomRepository cbomRepository;

    @Autowired
    private CryptoAssetRepository assetRepository;

    @Test
    void listsTheAssetsADocumentContributedWithTheRefsTheyWereFoldedFrom() throws NotFoundException {
        seedAnotherDocumentsContribution();
        Cbom cbom = cbom("urn:uuid:contributions", 1);
        ingest(cbom, threeComponentsTwoAssets());

        PaginationResponseDto<CbomContributedAssetDto> page = list(cbom.getUuid());

        assertThat(page.getTotalItems()).isEqualTo(2);
        assertThat(page.getItems()).extracting(CbomContributedAssetDto::getName).containsExactly("aes-256", "rsa-2048");
        assertThat(page.getItems().get(0).getBomRefs()).containsExactly("a1", "a2");
        assertThat(page.getItems().get(1).getBomRefs()).containsExactly("b");
        assertThat(page.getItems().get(0).getSourceCbomCount()).isEqualTo(1);
        assertThat(page.getItems().get(0).getUuid()).isEqualTo(assetNamed("aes-256"));
    }

    @Test
    void aCbomThatContributedNothingListsAnEmptyPage() throws NotFoundException {
        seedAnotherDocumentsContribution();
        Cbom cbom = cbom("urn:uuid:nothing", 1);

        PaginationResponseDto<CbomContributedAssetDto> page = list(cbom.getUuid());

        assertThat(page.getItems()).isEmpty();
        assertThat(page.getTotalItems()).isZero();
        assertThat(page.getPageNumber()).isEqualTo(1);
    }

    /** A repeated bom-ref refuses the document whole, so nothing of it is listed -- no component links to anything. */
    @Test
    void aDocumentThatRepeatsABomRefIsRefusedAndListsNothing() throws NotFoundException {
        seedAnotherDocumentsContribution();
        Cbom cbom = cbom("urn:uuid:repeated", 1);
        JsonNode repeated = CbomIngestTestFixtures
                .documentOf(CbomIngestTestFixtures.algorithmWithRef("AES-256", "dup"),
                        CbomIngestTestFixtures.algorithmWithRef("RSA-2048", "dup"));

        assertThat(ingestService.ingest(cbom.getUuid(), repeated, NOW, POLICY))
                .isEqualTo(CbomAssetIngestService.IngestOutcome.REFUSED);

        PaginationResponseDto<CbomContributedAssetDto> page = list(cbom.getUuid());
        assertThat(page.getTotalItems()).isZero();
        assertThat(page.getItems()).isEmpty();
    }

    /** A ref with no encoding links nothing; the asset is still listed, with an empty list rather than none. */
    @Test
    void aRefTheDocumentCannotEncodeLinksNothingButTheAssetIsListed() throws NotFoundException {
        Cbom cbom = cbom("urn:uuid:unencodable", 1);
        ingest(cbom, CbomIngestTestFixtures
                .read("{\"components\":[{\"type\":\"cryptographic-asset\",\"bom-ref\":\"\\ud800\",\"name\":\"AES-256\","
                        + "\"cryptoProperties\":{\"assetType\":\"algorithm\",\"algorithmProperties\":{}}}]}"));

        PaginationResponseDto<CbomContributedAssetDto> page = list(cbom.getUuid());

        assertThat(page.getItems()).singleElement().satisfies(row -> assertThat(row.getBomRefs()).isEmpty());
    }

    /** The uuid names one version: the superseded one lists nothing, the current one its own refs. */
    @Test
    void theListingIsScopedToTheVersionTheUuidNames() throws NotFoundException {
        Cbom first = cbom("urn:uuid:app", 1);
        ingest(first, CbomIngestTestFixtures.documentOf(CbomIngestTestFixtures.algorithmWithRef("AES-256", "v1-aes")));
        Cbom second = cbom("urn:uuid:app", 2);
        ingest(second,
                CbomIngestTestFixtures
                        .documentOf(CbomIngestTestFixtures.algorithmWithRef("AES-256", "v2-aes"),
                                CbomIngestTestFixtures.algorithmWithRef("RSA-2048", "v2-rsa")));

        assertThat(list(first.getUuid()).getTotalItems())
                .describedAs("the superseded version sources nothing")
                .isZero();
        PaginationResponseDto<CbomContributedAssetDto> current = list(second.getUuid());
        assertThat(current.getItems())
                .extracting(CbomContributedAssetDto::getBomRefs)
                .containsExactly(List.of("v2-aes"), List.of("v2-rsa"));
    }

    /** An asset two documents share carries each document's own refs, never the union. */
    @Test
    void anotherDocumentsContributionsAreNotListed() throws NotFoundException {
        Cbom x = cbom("urn:uuid:x", 1);
        Cbom y = cbom("urn:uuid:y", 1);
        ingest(x,
                CbomIngestTestFixtures
                        .documentOf(CbomIngestTestFixtures.algorithmWithRef("AES-256", "x-aes"),
                                CbomIngestTestFixtures.algorithmWithRef("RSA-2048", "x-rsa")));
        ingest(y, CbomIngestTestFixtures.documentOf(CbomIngestTestFixtures.algorithmWithRef("AES-256", "y-aes")));

        PaginationResponseDto<CbomContributedAssetDto> ofX = list(x.getUuid());
        PaginationResponseDto<CbomContributedAssetDto> ofY = list(y.getUuid());

        assertThat(ofX.getItems())
                .extracting(CbomContributedAssetDto::getBomRefs)
                .containsExactly(List.of("x-aes"), List.of("x-rsa"));
        assertThat(ofY.getItems()).singleElement().satisfies(row -> {
            assertThat(row.getName()).isEqualTo("aes-256");
            assertThat(row.getBomRefs()).containsExactly("y-aes");
            assertThat(row.getSourceCbomCount()).describedAs("the row is the inventory row").isEqualTo(2);
        });
    }

    /** The caller's asset scope applies exactly as on the inventory listing: a forbidden asset is left out. */
    @Test
    void anAssetTheCallerMayNotListIsLeftOut() throws NotFoundException {
        Cbom cbom = cbom("urn:uuid:scoped", 1);
        ingest(cbom, threeComponentsTwoAssets());
        forbidCryptoAssetObjects(List.of(assetNamed("aes-256")));

        PaginationResponseDto<CbomContributedAssetDto> page = list(cbom.getUuid());

        assertThat(page.getTotalItems()).isEqualTo(1);
        assertThat(page.getItems()).singleElement().satisfies(row -> assertThat(row.getName()).isEqualTo("rsa-2048"));
    }

    @Test
    void theInventoryFiltersApply() throws NotFoundException {
        Cbom cbom = cbom("urn:uuid:filtered", 1);
        ingest(cbom, threeComponentsTwoAssets());
        SearchRequestDto request = new SearchRequestDto();
        request.setFilters(List.of(aPropertyEqualsFilter(FilterField.CBOM_ASSET_NAME, "rsa-2048")));

        PaginationResponseDto<CbomContributedAssetDto> page = cbomService
                .listCbomAssets(SecuredUUID.fromUUID(cbom.getUuid()), request, SecurityFilter.create());

        assertThat(page.getTotalItems()).isEqualTo(1);
        assertThat(page.getItems()).singleElement().satisfies(row -> assertThat(row.getBomRefs()).containsExactly("b"));
    }

    @Test
    void anUnknownCbomIsNotFound() {
        assertThatThrownBy(() -> list(UUID.randomUUID())).isInstanceOf(NotFoundException.class);
    }

    @Test
    void sortingIsRefusedLikeTheInventoryListing() {
        Cbom cbom = cbom("urn:uuid:sorted", 1);
        SearchRequestDto request = new SearchRequestDto();
        request
                .setSort(new SearchSortRequestDto(FilterFieldSource.PROPERTY, FilterField.CBOM_ASSET_NAME.name(),
                        SortDirection.ASC));

        assertThatThrownBy(() -> cbomService
                .listCbomAssets(SecuredUUID.fromUUID(cbom.getUuid()), request, SecurityFilter.create()))
                .isInstanceOf(ValidationException.class)
                .hasMessageContaining("Sorting");
    }

    private PaginationResponseDto<CbomContributedAssetDto> list(UUID cbomUuid) throws NotFoundException {
        return cbomService
                .listCbomAssets(SecuredUUID.fromUUID(cbomUuid), new SearchRequestDto(), SecurityFilter.create());
    }

    private void ingest(Cbom cbom, JsonNode document) {
        assertThat(ingestService.ingest(cbom.getUuid(), document, NOW, POLICY))
                .isEqualTo(CbomAssetIngestService.IngestOutcome.INGESTED);
    }

    /**
     * Puts another document's asset in the inventory first, so a listing that lost its scope to the record the uuid
     * names would serve that asset too; an empty inventory lists nothing whatever the scope.
     */
    private void seedAnotherDocumentsContribution() throws NotFoundException {
        Cbom other = cbom("urn:uuid:other", 1);
        ingest(other,
                CbomIngestTestFixtures.documentOf(CbomIngestTestFixtures.algorithmWithRef("SHA-256", "other-sha")));
        assertThat(list(other.getUuid()).getTotalItems())
                .describedAs("the other document's contribution is in the inventory")
                .isEqualTo(1);
    }

    private static JsonNode threeComponentsTwoAssets() {
        return CbomIngestTestFixtures
                .documentOf(CbomIngestTestFixtures.algorithmWithRef("AES-256", "a1"),
                        CbomIngestTestFixtures.algorithmWithRef("RSA-2048", "b"),
                        CbomIngestTestFixtures.algorithmWithRef("AES-256", "a2"));
    }

    private Cbom cbom(String serialNumber, int version) {
        Cbom cbom = new Cbom();
        cbom.setSerialNumber(serialNumber);
        cbom.setVersion(version);
        cbom.setSpecVersion("1.7");
        return cbomRepository.save(cbom);
    }

    private UUID assetNamed(String name) {
        return assetRepository
                .findAll()
                .stream()
                .filter(asset -> name.equals(asset.getName()))
                .map(CryptoAsset::getUuid)
                .findFirst()
                .orElseThrow(() -> new AssertionError("no asset named " + name));
    }

    /**
     * Stubs the OPA object-access vote for {@code cryptoAssets:list} so every uuid in {@code forbidden} is denied while
     * the rest stays visible -- a partial restriction, the twin of
     * {@code CryptographicAssetStatisticsITest#forbidCryptoAssetObjects}.
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
}
