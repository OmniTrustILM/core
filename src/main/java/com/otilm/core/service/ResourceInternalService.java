package com.otilm.core.service;

import com.otilm.api.exception.AttributeException;
import com.otilm.api.exception.ConnectorException;
import com.otilm.api.exception.NotFoundException;
import com.otilm.api.model.client.certificate.SearchFilterRequestDto;
import com.otilm.api.model.common.NameAndUuidDto;
import com.otilm.api.model.common.attribute.common.DataAttribute;
import com.otilm.api.model.common.attribute.common.callback.AttributeCallback;
import com.otilm.api.model.common.attribute.common.callback.RequestAttributeCallback;
import com.otilm.api.model.common.attribute.v3.content.data.ResourceObjectContentData;
import com.otilm.api.model.core.auth.AttributeResource;
import com.otilm.api.model.core.auth.Resource;
import com.otilm.api.model.core.other.ResourceObjectDto;
import com.otilm.api.model.core.scheduler.PaginationRequestDto;

import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;

public interface ResourceInternalService {

    /**
     * Function to get the object for specified resource, for external use with authorization check
     *
     * @param resource resource
     * @param objectUuid object UUID
     * @return ResourceObjectDto object
     */
    ResourceObjectDto getResourceObject(Resource resource, UUID objectUuid) throws NotFoundException;

    /**
     * Function to get the object for specified resource, for internal use without authorization
     *
     * @param resource resource
     * @param objectUuid object UUID
     * @return ResourceObjectDto object
     */
    ResourceObjectDto getResourceObjectInternal(Resource resource, UUID objectUuid) throws NotFoundException;

    /**
     * Function to get the list of objects available for a resource, for internal/system use without authorization.
     *
     * @param resource resource
     * @param filters filters for the resource objects
     * @param pagination pagination of the response
     * @return List of NameAndUuidDto
     */
    List<NameAndUuidDto> getResourceObjectsInternal(Resource resource, List<SearchFilterRequestDto> filters,
            PaginationRequestDto pagination) throws NotFoundException;

    boolean hasResourceExtensionService(Resource resource);

    void loadResourceObjectContentData(AttributeCallback callback, RequestAttributeCallback requestAttributeCallback,
            Map<String, AttributeResource> resources) throws NotFoundException, AttributeException, ConnectorException;

    void loadResourceObjectContentData(List<DataAttribute> attributes)
            throws NotFoundException, AttributeException, ConnectorException;

    /**
     * The content of one referenced object, as a connector request carries it. Checks no permission on the object
     * itself, like {@link #loadResourceObjectContentData(List)}: only system-mode resolution may call it, under the
     * system identity that is authorized at the operation level.
     *
     * @throws NotFoundException when the object does not exist
     */
    ResourceObjectContentData loadReferencedObjectContent(AttributeResource resource, UUID uuid)
            throws NotFoundException, AttributeException, ConnectorException;

    /**
     * The connector a referenced object belongs to, when Core may lend that connector the object's own references.
     * Checks no permission.
     */
    Optional<UUID> findOwningConnector(AttributeResource resource, UUID uuid);
}
