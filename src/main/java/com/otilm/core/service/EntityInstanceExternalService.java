package com.otilm.core.service;

import com.otilm.api.exception.AlreadyExistException;
import com.otilm.api.exception.AttributeException;
import com.otilm.api.exception.ConnectorException;
import com.otilm.api.exception.NotFoundException;
import com.otilm.api.model.client.attribute.RequestAttribute;
import com.otilm.api.model.client.certificate.EntityInstanceResponseDto;
import com.otilm.api.model.client.certificate.SearchRequestDto;
import com.otilm.api.model.client.entity.EntityInstanceUpdateRequestDto;
import com.otilm.api.model.common.attribute.common.BaseAttribute;
import com.otilm.api.model.core.entity.EntityInstanceDto;
import com.otilm.api.model.core.search.SearchFieldDataByGroupDto;
import com.otilm.core.security.authz.SecuredUUID;
import com.otilm.core.security.authz.SecurityFilter;

import java.util.List;

public interface EntityInstanceExternalService {

    /**
     * List available Entity instances
     * @return List of available Entity instances
     */
    EntityInstanceResponseDto listEntityInstances(SecurityFilter filter, SearchRequestDto requestDto);

    /**
     * Get Entity instance by UUID
     * @param entityUuid UUID of Entity instance
     * @return Entity instance
     * @throws NotFoundException when Entity instance with given UUID is not found
     * @throws ConnectorException when failed to get Entity instance information
     */
    EntityInstanceDto getEntityInstance(SecuredUUID entityUuid) throws NotFoundException, ConnectorException;

    /**
     * Create Entity instance
     * @param entityInstanceRequestDto Request to create Entity instance, see {@link EntityInstanceUpdateRequestDto}
     * @return Created Entity instance
     * @throws AlreadyExistException when Entity instance already exists
     * @throws ConnectorException when failed to create Entity instance
     */
    EntityInstanceDto createEntityInstance(com.otilm.api.model.client.entity.EntityInstanceRequestDto entityInstanceRequestDto) throws AlreadyExistException, ConnectorException, AttributeException, NotFoundException;

    /**
     * Update Entity instance
     * @param entityUuid UUID of Entity instance
     * @param entityInstanceUpdateRequestDto Request to update Entity instance, see {@link EntityInstanceUpdateRequestDto}
     * @return Updated Entity instance
     * @throws NotFoundException when Entity instance with given UUID is not found
     * @throws ConnectorException when failed to update Entity instance
     */
    EntityInstanceDto editEntityInstance(SecuredUUID entityUuid, EntityInstanceUpdateRequestDto entityInstanceUpdateRequestDto) throws NotFoundException, ConnectorException, AttributeException;

    /**
     * Delete Entity instance
     * @param entityUuid UUID of Entity instance
     * @throws NotFoundException when Entity instance with given UUID is not found
     * @throws ConnectorException when failed to delete Entity instance
     */

    void deleteEntityInstance(SecuredUUID entityUuid) throws NotFoundException, ConnectorException;

    /**
     * List Location Attributes supported by  Entity instance
     *
     * @param entityUuid UUID of Entity instance
     * @return List of Location Attributes supported by Entity instance
     * @throws NotFoundException  when Entity instance with given UUID is not found
     * @throws ConnectorException when failed to get Location Attributes
     */
    List<BaseAttribute> listLocationAttributes(SecuredUUID entityUuid) throws NotFoundException, ConnectorException;

    /**
     * Validate Location Attributes for Entity instance
     * @param entityUuid UUID of Entity instance
     * @param locationAttributes Request Attributes to validate, see {@link RequestAttribute}
     * @throws NotFoundException when Entity instance with given UUID is not found
     * @throws ConnectorException when failed to validate Location Attributes
     */
    void validateLocationAttributes(SecuredUUID entityUuid, List<RequestAttribute> locationAttributes) throws NotFoundException, ConnectorException;

    /**
     * Get all possible field to be able to search by customer
     * @return List of {@link SearchFieldDataByGroupDto} object with definition the possible fields
     */
    List<SearchFieldDataByGroupDto> getSearchableFieldInformationByGroup();
}
