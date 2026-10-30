package com.otilm.core.service;

import com.otilm.api.exception.NotFoundException;
import com.otilm.api.model.client.certificate.SearchRequestDto;
import com.otilm.api.model.client.dashboard.CryptographicAssetStatisticsDto;
import com.otilm.api.model.common.PaginationResponseDto;
import com.otilm.api.model.core.cbom.CbomContributedAssetDto;
import com.otilm.api.model.core.cryptoasset.CryptographicAssetDetailDto;
import com.otilm.api.model.core.cryptoasset.CryptographicAssetDto;
import com.otilm.api.model.core.cryptoasset.CryptographicAssetPqcExplanationDto;
import com.otilm.api.model.core.search.SearchFieldDataByGroupDto;
import com.otilm.core.security.authz.SecuredUUID;
import com.otilm.core.security.authz.SecurityFilter;
import java.util.List;
import java.util.UUID;

/**
 * Read side of the cryptographic asset inventory — the deduplicated cross-CBOM asset view served under
 * {@code /v1/cryptoAssets}. Assets enter the inventory through the CBOM document sync, so this service has no asset
 * creation or deletion operations. Custom attribute content is updated through the generic resource endpoint.
 *
 * <p>
 * The ratified contract (interfaces#909, interfaces#913) is fully served: list, detail, the searchable-field
 * definitions and the dashboard statistics are all real reads. The authorization annotations on the implementation are
 * what gate every operation, so the resource and its actions reach the auth service before the data does and an
 * unpermitted caller is refused with 403.
 */
public interface CryptographicAssetExternalService {

    /**
     * List one page of the deduplicated cross-CBOM asset inventory, narrowed by the filters in the request.
     *
     * @param filter security filter narrowing the result to the caller's permitted objects
     * @param request search request carrying the filters, sort and paging
     * @return one page of matching assets
     */
    PaginationResponseDto<CryptographicAssetDto> listCryptographicAssets(SecurityFilter filter,
            SearchRequestDto request);

    /**
     * One page of the assets one CBOM record contributed.
     *
     * <p>
     * <b>Scope:</b> the inventory listing narrowed to one source document and one version of it. It takes the same
     * filters, sort and columns as {@link #listCryptographicAssets}.
     *
     * <p>
     * <b>Rows:</b> each row is the inventory row, with its inventory-wide counts and projected attribute values, plus
     * the {@code bom-ref} values of this document's components folded into it.
     *
     * <p>
     * <b>Authorization:</b> gated as {@code CRYPTO_ASSET/LIST}, so the caller's asset scope applies as on the inventory
     * listing. This method does not check access to the CBOM: its caller, {@code
     * CbomExternalService#listCbomAssets}, must.
     *
     * @param cbomUuid the CBOM record whose contributions are listed; a record with none yields an empty page
     */
    PaginationResponseDto<CbomContributedAssetDto> listCbomContributedAssets(UUID cbomUuid, SearchRequestDto request,
            SecurityFilter filter);

    /**
     * Retrieve one asset with its verdict provenance, normalized properties, per-source payloads and recorded object
     * identifiers.
     *
     * @param uuid secured unique identifier of the asset
     * @return the asset detail
     * @throws NotFoundException if no asset with the given UUID is in the inventory
     */
    CryptographicAssetDetailDto getCryptographicAsset(SecuredUUID uuid) throws NotFoundException;

    /**
     * Recompute one asset's PQC verdict rule by rule from the row as stored. Nothing is written back.
     *
     * @param uuid secured unique identifier of the asset
     * @return the explanation, with whether it agrees with the stored verdict
     * @throws NotFoundException if no asset with the given UUID is in the inventory
     */
    CryptographicAssetPqcExplanationDto getCryptographicAssetPqcExplanation(SecuredUUID uuid) throws NotFoundException;

    /**
     * Fields the list operation accepts in its filters, grouped by field source.
     *
     * @return the searchable field definitions
     */
    List<SearchFieldDataByGroupDto> getSearchableFieldInformationByGroup();

    /**
     * Count badges, distribution maps and the sync-completeness block for the inventory dashboard. Shares the list
     * permission with {@link #listCryptographicAssets} rather than carrying a gate of its own.
     *
     * @param filter security filter narrowing the asset-side counts to the caller's permitted objects; the
     * document-level completeness block is scoped separately, by CBOM object access
     * @return the dashboard statistics
     */
    CryptographicAssetStatisticsDto getCryptographicAssetStatistics(SecurityFilter filter);
}
