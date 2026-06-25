package com.otilm.core.service;

import com.otilm.api.exception.*;
import com.otilm.api.model.client.certificate.LocationsResponseDto;
import com.otilm.api.model.client.certificate.SearchRequestDto;
import com.otilm.api.model.client.location.AddLocationRequestDto;
import com.otilm.api.model.client.location.EditLocationRequestDto;
import com.otilm.api.model.client.location.IssueToLocationRequestDto;
import com.otilm.api.model.client.location.PushToLocationRequestDto;
import com.otilm.api.model.common.attribute.common.BaseAttribute;
import com.otilm.api.model.core.location.LocationDto;
import com.otilm.api.model.core.search.SearchFieldDataByGroupDto;
import com.otilm.core.security.authz.SecuredParentUUID;
import com.otilm.core.security.authz.SecuredUUID;
import com.otilm.core.security.authz.SecurityFilter;

import java.util.List;

public interface LocationExternalService {

    /**
     * List all locations based on the status.
     *
     * @return List of locations.
     */
    LocationsResponseDto listLocations(SecurityFilter filter, SearchRequestDto searchRequestDto);

    /**
     * Add a new location.
     *
     * @param addLocationRequestDto Request containing Attributes for the Location, see {@link AddLocationRequestDto}.
     * @param entityUuid            Entity Uuid.
     * @return New Location created.
     * @throws AlreadyExistException when the Location with the same name already exists.
     * @throws LocationException     when the Location failed to be created.
     * @throws NotFoundException     when the Entity instance referred in the Location is not found.
     */
    LocationDto addLocation(SecuredParentUUID entityUuid, AddLocationRequestDto addLocationRequestDto) throws AlreadyExistException, LocationException, ConnectorException, AttributeException, NotFoundException;

    /**
     * Get existing Location by UUID.
     *
     * @param locationUuid UUID of existing Location.
     * @return Location with the given UUID.
     * @throws NotFoundException when the Location with the given UUID is not found.
     */
    LocationDto getLocation(SecuredParentUUID entityUuid, SecuredUUID locationUuid) throws NotFoundException;

    /**
     * Edit an existing Location.
     *
     * @param entityUuid             Entity Instance UUID
     * @param locationUuid           UUID of existing Location.
     * @param editLocationRequestDto Request containing Attributes for the Location, see {@link EditLocationRequestDto}.
     * @return Edited Location.
     * @throws NotFoundException when the Location with the given UUID is not found.
     * @throws LocationException when the Location failed to be edited.
     */
    LocationDto editLocation(SecuredParentUUID entityUuid, SecuredUUID locationUuid, EditLocationRequestDto editLocationRequestDto) throws ConnectorException, LocationException, AttributeException, NotFoundException;

    /**
     * Remove existing Location with the given UUID.
     *
     * @param locationUuid UUID of existing Location.
     * @throws NotFoundException   when the Location with the given UUID is not found.
     * @throws ValidationException when the Location contains associated Certificates.
     */
    void deleteLocation(SecuredParentUUID entityUuid, SecuredUUID locationUuid) throws NotFoundException;

    /**
     * Enable existing Location with the given UUID.
     *
     * @param locationUuid UUID of existing Location.
     * @throws NotFoundException when the Location with the given UUID is not found.
     */
    void enableLocation(SecuredParentUUID entityUuid, SecuredUUID locationUuid) throws NotFoundException;

    /**
     * Disable existing Location with the given UUID.
     *
     * @param locationUuid UUID of existing Location.
     * @throws NotFoundException when the Location with the given UUID is not found.
     */
    void disableLocation(SecuredParentUUID entityUuid, SecuredUUID locationUuid) throws NotFoundException;

    /**
     * List all push Attributes for the given Location.
     *
     * @param entityUuid   UUID of entity
     * @param locationUuid UUID of existing Location.
     * @return List of push Attributes.
     * @throws NotFoundException when the Location with the given UUID is not found.
     * @throws LocationException when the push Attributes failed to be retrieved from the Location.
     */
    List<BaseAttribute> listPushAttributes(SecuredParentUUID entityUuid, SecuredUUID locationUuid) throws NotFoundException, LocationException;

    /**
     * List all issue Attributes for the given Location.
     *
     * @param entityUuid   UUID of entity
     * @param locationUuid UUID of existing Location.
     * @return List of issue Attributes.
     * @throws NotFoundException when the Location with the given UUID is not found.
     * @throws LocationException when the issue Attributes failed to be retrieved from the Location.
     */
    List<BaseAttribute> listCsrAttributes(SecuredParentUUID entityUuid, SecuredUUID locationUuid) throws NotFoundException, LocationException;

    /**
     * Remove existing Certificate from the given Location.
     *
     * @param entityUuid      UUID of entity
     * @param locationUuid    UUID of existing Location.
     * @param certificateUuid UUID of existing Certificate.
     * @return Location detail with the removed Certificate.
     * @throws NotFoundException when the Location or Certificate with the given UUID is not found.
     * @throws LocationException when the Certificate failed to be removed from the Location.
     */
    LocationDto removeCertificateFromLocation(SecuredParentUUID entityUuid, SecuredUUID locationUuid, String certificateUuid) throws NotFoundException, LocationException;

    /**
     * Push existing Certificate to the given Location.
     *
     * @param entityUuid               UUID of entity
     * @param locationUuid             UUID of existing Location.
     * @param certificateUuid          UUID of existing Certificate.
     * @param pushToLocationRequestDto Request containing information to push the Certificate, see {@link PushToLocationRequestDto}.
     * @return Location detail with the pushed Certificate.
     * @throws NotFoundException when the Location or Certificate with the given UUID is not found.
     * @throws LocationException when the Certificate failed to be pushed to the Location.
     */
    LocationDto pushCertificateToLocation(SecuredParentUUID entityUuid, SecuredUUID locationUuid, String certificateUuid, PushToLocationRequestDto pushToLocationRequestDto) throws NotFoundException, LocationException, AttributeException;

    /**
     * Issue new Certificate to the given Location.
     *
     * @param entityUuid                UUID of entity
     * @param locationUuid              UUID of existing Location.
     * @param issueToLocationRequestDto Request containing information to issue the Certificate, see {@link IssueToLocationRequestDto}.
     * @return Location detail with the issued Certificate.
     * @throws NotFoundException when the Location with the given UUID is not found.
     * @throws LocationException when the Certificate failed to be issued to the Location.
     */
    LocationDto issueCertificateToLocation(SecuredParentUUID entityUuid, SecuredUUID locationUuid, String raProfileUuid, IssueToLocationRequestDto issueToLocationRequestDto) throws NotFoundException, LocationException, ConnectorException;

    /**
     * Synchronize and update content for the given Location.
     *
     * @param entityUuid   UUID of entity
     * @param locationUuid UUID of existing Location.
     * @return Location detail with the updated content.
     * @throws NotFoundException when the Location with the given UUID is not found.
     * @throws LocationException when the content failed to be synchronized from the Location.
     */
    LocationDto updateLocationContent(SecuredParentUUID entityUuid, SecuredUUID locationUuid) throws NotFoundException, LocationException;

    /**
     * Renew the Certificate for the given Location.
     *
     * @param entityUuid      UUID of entity
     * @param locationUuid    UUID of existing Location.
     * @param certificateUuid UUID of existing Certificate.
     * @return Location detail with the renewed Certificate.
     * @throws NotFoundException when the Location or Certificate with the given UUID is not found.
     * @throws LocationException when the Certificate failed to be renewed in the Location.
     */
    LocationDto renewCertificateInLocation(SecuredParentUUID entityUuid, SecuredUUID locationUuid, String certificateUuid) throws NotFoundException, LocationException, ConnectorException;

    /**
     * Get all possible field to be able to search by customer
     *
     * @return List of {@link SearchFieldDataByGroupDto} object with definition the possible fields
     */
    List<SearchFieldDataByGroupDto> getSearchableFieldInformationByGroup();
}
