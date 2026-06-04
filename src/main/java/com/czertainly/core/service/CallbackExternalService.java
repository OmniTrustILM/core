package com.czertainly.core.service;

import com.czertainly.api.exception.AttributeException;
import com.czertainly.api.exception.ConnectorException;
import com.czertainly.api.exception.NotFoundException;
import com.czertainly.api.exception.ValidationException;
import com.czertainly.api.model.common.attribute.common.callback.RequestAttributeCallback;
import com.czertainly.api.model.core.auth.Resource;
import com.czertainly.api.model.core.connector.FunctionGroupCode;

import java.util.UUID;

public interface CallbackExternalService {

    /**
     * Function to execute the callback on the connector. This method executes the callback only for the attributes
     * that are derived from the primary objects of the connector
     * @param uuid UUID of the connector
     * @param functionGroup Function group of the connector
     * @param kind Kind of the connector
     * @param callback Callback request containing information regarding the
     * @return Callback
     * @throws ConnectorException when there are issues with the connector communication
     * @throws ValidationException when there are issues with the validation of callback items
     */
    Object callback(
            String uuid,
            FunctionGroupCode functionGroup,
            String kind,
            RequestAttributeCallback callback
    ) throws ConnectorException, ValidationException, NotFoundException, AttributeException;

    /**
     * Function to execute the callback on the connector. This method executes the callback for the attributes
     * defined by the connector
     * @param uuid UUID of the connector
     * @param callback Callback request containing information regarding the callback and the callback mappings
     * @return Callback
     */
    Object callback(UUID uuid, RequestAttributeCallback callback) throws NotFoundException, ConnectorException, AttributeException;

    /**
     * Function to execute the callback on the connector. This method executes the callback only for the attributes
     * that are derived from the primary objects of the connector
     * @param resource Type of the resource for which the callback has to be executed
     * @param resourceUuid UUID of the resource to which the callback will be executed
     * @param callback Callback request containing information regarding the
     * @return Callback
     * @throws ConnectorException when there are issues with the connector communication
     * @throws ValidationException when there are issues with the validation of callback items
     */
    Object resourceCallback(
            Resource resource,
            String resourceUuid,
            RequestAttributeCallback callback
    ) throws ConnectorException, ValidationException, NotFoundException, AttributeException;
}
