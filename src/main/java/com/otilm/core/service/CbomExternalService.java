package com.otilm.core.service;

import java.util.List;
import java.util.UUID;

import com.otilm.api.exception.AlreadyExistException;
import com.otilm.api.exception.CbomRepositoryException;
import com.otilm.api.exception.NotFoundException;
import com.otilm.api.exception.ValidationException;
import com.otilm.api.model.client.certificate.SearchRequestDto;
import com.otilm.api.model.common.BulkActionMessageDto;
import com.otilm.api.model.common.PaginationResponseDto;
import com.otilm.api.model.core.cbom.CbomDetailDto;
import com.otilm.api.model.core.cbom.CbomDto;
import com.otilm.api.model.core.cbom.CbomUploadRequestDto;
import com.otilm.api.model.core.search.SearchFieldDataByGroupDto;
import com.otilm.core.security.authz.SecuredUUID;
import com.otilm.core.security.authz.SecurityFilter;

public interface CbomExternalService {
    /**
     * List available CBOMs
     * @return List of available CBOMs
     */
    PaginationResponseDto<CbomDto> listCboms(SecurityFilter filter, SearchRequestDto request);

    /**
     * Retrieves detailed information about a specific CBOM
     * from cbom-repository.
     *
     * @param uuid Secured unique identifier of the CBOM to retrieve
     * @return {@link CbomDetailDto} containing the complete CBOM details
     * @throws CbomRepositoryException if there is an error accessing the CBOM repository
     * @throws NotFoundException if the CBOM with the specified UUID does not exist
     */
    CbomDetailDto getCbomDetail(SecuredUUID uuid) throws CbomRepositoryException, NotFoundException;

    /**
     * Return versions of CBOM with same serial number from DB
     * @param uuid Secured unique identifier of the CBOM to retrieve
     * @return List of uuid/urn/version
     * @throws NotFoundException if the CBOM with the specified UUID does not exist
     */
    List<CbomDto> getCbomVersions(SecuredUUID uuid) throws NotFoundException;

    /**
     * Upload CBOM into cbom-repository and store cbom statistics in database.
     * @param request is upload request, see {@link CbomUploadRequestDto}
     * @return Stats of created instance
     * @throws AlreadyExistException if a CBOM with given serial number exists
     * @throws CbomRepositoryException for a unspecified problem with accessing cbom-repository (like HTTP 502)
     * @throws ValidationException if CBOM does not pass the cbom-repository validation
     */
    CbomDto createCbom(CbomUploadRequestDto request) throws AlreadyExistException, CbomRepositoryException, ValidationException;

    /**
     * Delete CBOM entry. The method will try to delete the CBOM.
     * @param uuid UUID of CBOM to be deleted
     * @throws NotFoundException if the CBOM with the specified UUID does not exist
     */
    void deleteCbom(UUID uuid) throws NotFoundException;

    /**
     * Bulk delete CBOM entries. The method will try to delete all CBOMs and return the result if some of them failed to be deleted.
     * @param uuids List of UUIDs of CBOMs to be deleted
     * @return List of {@link BulkActionMessageDto} with the failed message of deletion for CBOM
     */
    List<BulkActionMessageDto> bulkDeleteCbom(List<UUID> uuids);

    /**
     * Get all searchable fields for CBOM filtering
     * @return List of {@link SearchFieldDataByGroupDto} object with definition the possible fields
     */
    List<SearchFieldDataByGroupDto> getSearchableFieldInformationByGroup();

    /**
     * Synchronize CBOMs from the CBOM repository. This version is intended for use
     * by the REST API controller as it requires authorization.
     *
     * @throws CbomRepositoryException if there are problems accessing the CBOM repository
     */
    void syncAuthorized() throws CbomRepositoryException;
}
