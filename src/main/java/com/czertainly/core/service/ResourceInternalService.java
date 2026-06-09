package com.czertainly.core.service;

import com.czertainly.api.exception.AttributeException;
import com.czertainly.api.exception.ConnectorException;
import com.czertainly.api.exception.NotFoundException;
import com.czertainly.api.model.client.certificate.SearchFilterRequestDto;
import com.czertainly.api.model.common.NameAndUuidDto;
import com.czertainly.api.model.common.attribute.common.DataAttribute;
import com.czertainly.api.model.common.attribute.common.callback.AttributeCallback;
import com.czertainly.api.model.common.attribute.common.callback.RequestAttributeCallback;
import com.czertainly.api.model.core.auth.AttributeResource;
import com.czertainly.api.model.core.auth.Resource;
import com.czertainly.api.model.core.other.ResourceObjectDto;
import com.czertainly.api.model.core.scheduler.PaginationRequestDto;

import java.util.List;
import java.util.Map;
import java.util.UUID;

public interface ResourceInternalService {

    /**
     * Function to get the object for specified resource, for external use with authorization check
     *
     * @param resource   resource
     * @param objectUuid object UUID
     * @return ResourceObjectDto object
     */
    ResourceObjectDto getResourceObject(Resource resource, UUID objectUuid) throws NotFoundException;

    /**
     * Function to get the object for specified resource, for internal use without authorization
     *
     * @param resource   resource
     * @param objectUuid object UUID
     * @return ResourceObjectDto object
     */
    ResourceObjectDto getResourceObjectInternal(Resource resource, UUID objectUuid) throws NotFoundException;

    /**
     * Function to get the list of objects available for a resource, for internal/system use without authorization.
     *
     * @param resource   resource
     * @param filters    filters for the resource objects
     * @param pagination pagination of the response
     * @return List of NameAndUuidDto
     */
    List<NameAndUuidDto> getResourceObjectsInternal(Resource resource, List<SearchFilterRequestDto> filters, PaginationRequestDto pagination) throws NotFoundException;

    boolean hasResourceExtensionService(Resource resource);

    void loadResourceObjectContentData(AttributeCallback callback, RequestAttributeCallback requestAttributeCallback, Map<String, AttributeResource> resources) throws NotFoundException, AttributeException, ConnectorException;

    void loadResourceObjectContentData(List<DataAttribute> attributes) throws NotFoundException, AttributeException, ConnectorException;
}
