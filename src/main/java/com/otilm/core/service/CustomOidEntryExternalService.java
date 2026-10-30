package com.otilm.core.service;

import com.otilm.api.exception.NotFoundException;
import com.otilm.api.model.client.certificate.SearchRequestDto;
import com.otilm.api.model.core.oid.CustomOidEntryDetailResponseDto;
import com.otilm.api.model.core.oid.CustomOidEntryListResponseDto;
import com.otilm.api.model.core.oid.CustomOidEntryRequestDto;
import com.otilm.api.model.core.oid.CustomOidEntryUpdateRequestDto;
import com.otilm.api.model.core.oid.OidCategory;
import com.otilm.api.model.core.search.SearchFieldDataByGroupDto;
import java.util.List;
import java.util.Set;

/**
 * Service for managing OID entries.
 */
public interface CustomOidEntryExternalService {

    /**
     * Creates a new custom OID entry.
     *
     * @param request the custom OID entry creation request
     * @return details of the created custom OID entry
     */
    CustomOidEntryDetailResponseDto createCustomOidEntry(CustomOidEntryRequestDto request);

    /**
     * Retrieves a custom OID entry by its OID value.
     *
     * @param oid the OID string
     * @return details of the requested custom OID entry
     */
    CustomOidEntryDetailResponseDto getCustomOidEntry(String oid) throws NotFoundException;

    /**
     * Edits an existing custom OID entry.
     *
     * @param oid the OID to update
     * @param request the update request data
     * @return updated basic information of the custom OID entry
     */
    CustomOidEntryDetailResponseDto editCustomOidEntry(String oid, CustomOidEntryUpdateRequestDto request)
            throws NotFoundException;

    /**
     * Deletes a custom OID entry by its OID.
     *
     * @param oid the OID to delete
     */
    void deleteCustomOidEntry(String oid) throws NotFoundException;

    /**
     * Deletes multiple custom OID entries in batch.
     *
     * @param oids list of OIDs to delete
     */
    void bulkDeleteCustomOidEntry(List<String> oids);

    /**
     * Returns a filtered and paginated list of custom OID entries.
     *
     * @param request search and pagination criteria
     * @return list of OID entry responses matching the criteria
     */
    CustomOidEntryListResponseDto listCustomOidEntries(SearchRequestDto request);

    /**
     * Returns the built-in system OID entries, optionally filtered by category.
     *
     * @param category optional category filter; when {@code null}, all system OIDs are returned
     * @return list of system OID entries
     */
    List<CustomOidEntryDetailResponseDto> listSystemOidEntries(OidCategory category);

    /**
     * OIDs held by a custom entry that a built-in system OID now shares. The custom entry wins, so the built-in
     * defaults do not apply; deleting it falls back to them. Empty when there is no conflict.
     *
     * <p>
     * Such a row can only arise from an upgrade: creating one is rejected because the OID is reserved, so every entry
     * here predates its OID's promotion to a system OID. The set therefore only grows at an upgrade and only shrinks as
     * operators resolve entries, and an empty set on a fresh install is the expected state rather than an unexercised
     * code path.
     */
    Set<String> getShadowedCustomOidEntries();

    /**
     * Returns a list of properties for filtering custom OID entries
     *
     * @return list of properties for filtering OID entries
     */
    List<SearchFieldDataByGroupDto> getSearchableFieldInformation();
}
