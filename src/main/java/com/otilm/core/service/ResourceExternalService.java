package com.otilm.core.service;

import com.otilm.api.exception.AttributeException;
import com.otilm.api.exception.NotFoundException;
import com.otilm.api.model.client.attribute.ResponseAttribute;
import com.otilm.api.model.client.certificate.SearchFilterRequestDto;
import com.otilm.api.model.common.NameAndUuidDto;
import com.otilm.api.model.common.attribute.common.AttributeContent;
import com.otilm.api.model.core.auth.Resource;
import com.otilm.api.model.core.other.ResourceDto;
import com.otilm.api.model.core.other.ResourceEvent;
import com.otilm.api.model.core.other.ResourceEventDto;
import com.otilm.api.model.core.scheduler.PaginationRequestDto;
import com.otilm.api.model.core.search.SearchFieldDataByGroupDto;
import com.otilm.core.security.authz.SecuredResource;
import com.otilm.core.security.authz.SecuredUUID;
import com.otilm.core.security.authz.SecurityFilter;

import java.util.List;
import java.util.Map;
import java.util.UUID;

public interface ResourceExternalService {

    /**
     * Method to retrieve resources available in platform
     *
     * @return List of resources
     */
    List<ResourceDto> listResources();

    /**
     * Function to get the list of objects available to be displayed for object level access for Access Control
     *
     * @param resource   Secured resource whose objects are being listed
     * @param filter     Security filter restricting the objects to those the principal may access
     * @param filters    Filters for the resource objects
     * @param pagination Pagination of the response
     * @return List of NameAndUuidDto
     */
    List<NameAndUuidDto> getResourceObjects(SecuredResource resource, SecurityFilter filter, List<SearchFilterRequestDto> filters, PaginationRequestDto pagination) throws NotFoundException;

    /**
     * Update the attribute content for the object
     *
     * @param resourceName  Name of the resource
     * @param objectUuid    UUID of the Object
     * @param attributeUuid UUID of the custom attribute
     * @param request       Attribute request with the content to be updated
     * @return List of attributes for the resource
     * @throws NotFoundException When the attribute or the object without the UUID is not found
     */
    List<ResponseAttribute> updateAttributeContentForObject(
            SecuredResource resourceName,
            SecuredUUID objectUuid,
            UUID attributeUuid,
            List<? extends AttributeContent> request
    ) throws NotFoundException, AttributeException;

    /**
     * Method to retrieve filter fields that can be used for creating rule conditions and actions
     *
     * @param resource Resource for which to retrieve filter fields
     * @param settable Indicator whether to retrieve only fields that can be set by an action
     * @return List of filter fields
     */
    List<SearchFieldDataByGroupDto> listResourceRuleFilterFields(Resource resource, boolean settable) throws NotFoundException;

    /**
     * Method to retrieve events supported by resource
     *
     * @param resource Resource for which to retrieve events
     * @return List of events
     */
    List<ResourceEventDto> listResourceEvents(Resource resource);

    /**
     * Method to retrieve all events supported by all resources
     *
     * @return Map of events
     */
    Map<ResourceEvent, List<ResourceEventDto>> listAllResourceEvents();
}
