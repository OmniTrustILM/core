package com.otilm.core.service;

import com.otilm.api.exception.AlreadyExistException;
import com.otilm.api.exception.AttributeException;
import com.otilm.api.exception.ConnectorException;
import com.otilm.api.exception.NotFoundException;
import com.otilm.api.exception.ValidationException;
import com.otilm.api.model.client.certificate.DiscoveryResponseDto;
import com.otilm.api.model.client.certificate.SearchRequestDto;
import com.otilm.api.model.client.discovery.DiscoveryCertificateResponseDto;
import com.otilm.api.model.client.discovery.DiscoveryDetailDto;
import com.otilm.api.model.client.discovery.DiscoveryDto;
import com.otilm.api.model.common.PaginationResponseDto;
import com.otilm.api.model.common.attribute.common.BaseAttribute;
import com.otilm.api.model.connector.discovery.v2.DiscoverySupportedResourceDto;
import com.otilm.api.model.core.auth.Resource;
import com.otilm.api.model.core.discovery.DiscoveryItemDto;
import com.otilm.api.model.core.discovery.DiscoveryMessageDto;
import com.otilm.api.model.core.search.SearchFieldDataByGroupDto;
import com.otilm.core.security.authz.SecuredUUID;
import com.otilm.core.security.authz.SecurityFilter;
import java.util.List;
import java.util.UUID;

public interface DiscoveryExternalService {

    DiscoveryResponseDto listDiscoveries(final SecurityFilter filter, final SearchRequestDto searchRequestDto);

    DiscoveryDetailDto getDiscovery(SecuredUUID uuid) throws NotFoundException;

    /**
     * List the certificates that are discovered as part of the discovery
     *
     * @param uuid UUID of the discovery
     * @param newlyDiscovered Boolean representing of the certificate is newly discovered or existing
     * @param itemsPerPage Pagination Item - Number of items per page
     * @param pageNumber Page number
     * @return List of certificates
     * @throws NotFoundException when the discovery with the UUID is not found
     */
    DiscoveryCertificateResponseDto getDiscoveryCertificates(SecuredUUID uuid, Boolean newlyDiscovered,
            int itemsPerPage, int pageNumber) throws NotFoundException;

    /**
     * One page of the run's advisory message log, oldest first — the detail counts these, this reads them.
     *
     * @param uuid secured identifier of the run whose log to read
     * @return the page; empty for a run that collected nothing, which is not the same as a run that does not exist
     * @throws NotFoundException if no discovery with the given UUID exists
     */
    PaginationResponseDto<DiscoveryMessageDto> getDiscoveryRunMessages(SecuredUUID uuid, int itemsPerPage,
            int pageNumber) throws NotFoundException;

    /**
     * One page of everything the run staged, certificates included — the single retrieval point for a run's results,
     * whichever store holds them.
     *
     * @param resource restrict to one resource type, or null for every one the run targeted
     * @param newlyDiscovered tri-state, matching {@code getDiscoveryCertificates}: null means both
     */
    PaginationResponseDto<DiscoveryItemDto> getDiscoveryItems(SecuredUUID uuid, Resource resource,
            Boolean newlyDiscovered, int itemsPerPage, int pageNumber) throws NotFoundException;

    /**
     * Asks the connector to checkpoint and pause the run.
     *
     * @throws ValidationException if the run is not in a state it can be stopped from, if its connector never declared
     * it stoppable, or if its connector generation cannot stop runs at all
     */
    void stopDiscovery(SecuredUUID uuid) throws NotFoundException, ConnectorException;

    /**
     * Restarts a stopped run from the connector's checkpoint. A connector that no longer holds one ends the run as
     * failed rather than refusing: the checkpoint cannot be recovered, so there is nothing left to resume.
     */
    void resumeDiscovery(SecuredUUID uuid) throws NotFoundException, ConnectorException;

    /** Ends the run and tells the connector to drop it. */
    void cancelDiscovery(SecuredUUID uuid) throws NotFoundException, ConnectorException;

    DiscoveryDetailDto createDiscovery(DiscoveryDto request, boolean saveEntity)
            throws AlreadyExistException, ConnectorException, AttributeException, NotFoundException;

    void runDiscoveryAsync(UUID discoveryUuid);

    void deleteDiscovery(SecuredUUID uuid) throws NotFoundException;

    void bulkRemoveDiscovery(List<SecuredUUID> discoveryUuids) throws NotFoundException;

    List<SearchFieldDataByGroupDto> getSearchableFieldInformationByGroup();

    /**
     * The resource types the connector's discovery interface can discover, relayed live. A connector implementing only
     * the v1 interface is answered with the single synthesized entry {@code certificates} and never called — a client
     * renders one shape for both generations.
     *
     * @param connectorUuid secured identifier of the connector, which is also what authorization is gated on
     * @throws NotFoundException if no connector with the given UUID exists
     */
    List<DiscoverySupportedResourceDto> listDiscoveryResources(SecuredUUID connectorUuid)
            throws NotFoundException, ConnectorException;

    /**
     * Relays the run-level attribute definitions from the connector's discovery interface.
     *
     * @throws ValidationException if the connector does not implement the v2 discovery interface, which is the only
     * generation that publishes an attribute schema
     */
    List<BaseAttribute> getDiscoveryAttributes(SecuredUUID connectorUuid) throws NotFoundException, ConnectorException;

    /**
     * Relays the attribute definitions refining discovery of one resource type.
     *
     * @param resource must be discoverable — the contract defines payloads for certificates and keys only
     */
    List<BaseAttribute> getDiscoveryResourceAttributes(SecuredUUID connectorUuid, Resource resource)
            throws NotFoundException, ConnectorException;
}
