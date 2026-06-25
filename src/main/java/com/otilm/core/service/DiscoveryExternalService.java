package com.otilm.core.service;

import com.otilm.api.exception.*;
import com.otilm.api.model.client.certificate.DiscoveryResponseDto;
import com.otilm.api.model.client.certificate.SearchRequestDto;
import com.otilm.api.model.client.discovery.DiscoveryCertificateResponseDto;
import com.otilm.api.model.client.discovery.DiscoveryDto;
import com.otilm.api.model.client.discovery.DiscoveryHistoryDetailDto;
import com.otilm.api.model.core.search.SearchFieldDataByGroupDto;
import com.otilm.core.security.authz.SecuredUUID;
import com.otilm.core.security.authz.SecurityFilter;

import java.util.List;
import java.util.UUID;

public interface DiscoveryExternalService {

    DiscoveryResponseDto listDiscoveries(final SecurityFilter filter, final SearchRequestDto searchRequestDto);

    DiscoveryHistoryDetailDto getDiscovery(SecuredUUID uuid) throws NotFoundException;

    /**
     * List the certificates that are discovered as part of the discovery
     *
     * @param uuid            UUID of the discovery
     * @param newlyDiscovered Boolean representing of the certificate is newly discovered or existing
     * @param itemsPerPage    Pagination Item - Number of items per page
     * @param pageNumber      Page number
     * @return List of certificates
     * @throws NotFoundException when the discovery with the UUID is not found
     */
    DiscoveryCertificateResponseDto getDiscoveryCertificates(SecuredUUID uuid, Boolean newlyDiscovered, int itemsPerPage, int pageNumber) throws NotFoundException;

    DiscoveryHistoryDetailDto createDiscovery(DiscoveryDto request, boolean saveEntity) throws AlreadyExistException, ConnectorException, AttributeException, NotFoundException;

    void runDiscoveryAsync(UUID discoveryUuid);

    void deleteDiscovery(SecuredUUID uuid) throws NotFoundException;

    void bulkRemoveDiscovery(List<SecuredUUID> discoveryUuids) throws NotFoundException;

    List<SearchFieldDataByGroupDto> getSearchableFieldInformationByGroup();
}
