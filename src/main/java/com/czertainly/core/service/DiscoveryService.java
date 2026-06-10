package com.czertainly.core.service;

import com.otilm.api.exception.*;
import com.otilm.api.model.client.certificate.DiscoveryResponseDto;
import com.otilm.api.model.client.certificate.SearchRequestDto;
import com.otilm.api.model.client.discovery.DiscoveryCertificateResponseDto;
import com.otilm.api.model.client.discovery.DiscoveryDto;
import com.otilm.api.model.client.discovery.DiscoveryHistoryDetailDto;
import com.otilm.api.model.core.search.SearchFieldDataByGroupDto;
import com.czertainly.core.security.authz.SecuredUUID;
import com.czertainly.core.security.authz.SecurityFilter;
import com.czertainly.core.tasks.ScheduledJobInfo;

import java.util.List;
import java.util.UUID;

public interface DiscoveryService extends ResourceExtensionService {

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
    DiscoveryHistoryDetailDto runDiscovery(UUID discoveryUuid, ScheduledJobInfo scheduledJobInfo);
    void runDiscoveryAsync(UUID discoveryUuid);

    void deleteDiscovery(SecuredUUID uuid) throws NotFoundException;

    void bulkRemoveDiscovery(List<SecuredUUID> discoveryUuids) throws NotFoundException;

    /**
     * Get the number of discoveries per user for dashboard
     *
     * @return Number of discoveries
     */
    Long statisticsDiscoveryCount(SecurityFilter filter);

    List<SearchFieldDataByGroupDto> getSearchableFieldInformationByGroup();

}
