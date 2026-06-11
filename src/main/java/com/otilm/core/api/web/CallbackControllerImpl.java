package com.otilm.core.api.web;

import com.otilm.api.exception.AttributeException;
import com.otilm.api.exception.ConnectorException;
import com.otilm.api.exception.NotFoundException;
import com.otilm.api.exception.ValidationException;
import com.otilm.api.interfaces.core.web.CallbackController;
import com.otilm.api.model.common.attribute.common.callback.RequestAttributeCallback;
import com.otilm.api.model.core.auth.Resource;
import com.otilm.api.model.core.connector.FunctionGroupCode;
import com.otilm.api.model.core.logging.enums.Module;
import com.otilm.api.model.core.logging.enums.Operation;
import com.otilm.core.aop.AuditLogged;
import com.otilm.core.logging.LogResource;
import com.otilm.core.service.CallbackExternalService;
import com.otilm.core.util.converter.ResourceCodeConverter;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.WebDataBinder;
import org.springframework.web.bind.annotation.InitBinder;
import org.springframework.web.bind.annotation.RestController;

import java.util.UUID;

@RestController
public class CallbackControllerImpl implements CallbackController {

    private CallbackExternalService callbackService;

    @Autowired
    public void setCallbackService(CallbackExternalService callbackService) {
        this.callbackService = callbackService;
    }

    @InitBinder
    public void initBinder(final WebDataBinder webdataBinder) {
        webdataBinder.registerCustomEditor(Resource.class, new ResourceCodeConverter());
    }

    @Override
    @AuditLogged(module = Module.CORE, resource = Resource.ATTRIBUTE, affiliatedResource = Resource.CONNECTOR, operation = Operation.ATTRIBUTE_CALLBACK)
    public Object callback(
            @LogResource(uuid = true, affiliated = true) String uuid,
            String functionGroup,
            @LogResource(name = true) String kind,
            RequestAttributeCallback callback
    ) throws NotFoundException, ConnectorException, ValidationException, AttributeException {
        return callbackService.callback(
                uuid,
                FunctionGroupCode.findByCode(functionGroup),
                kind,
                callback
        );
    }

    @Override
    @AuditLogged(module = Module.CORE, resource = Resource.ATTRIBUTE, affiliatedResource = Resource.CONNECTOR, operation = Operation.ATTRIBUTE_CALLBACK)
    public Object callback(UUID uuid, RequestAttributeCallback callback) throws ConnectorException, NotFoundException, AttributeException {
        return callbackService.callback(uuid, callback);
    }

    @Override
    @AuditLogged(module = Module.CORE, resource = Resource.ATTRIBUTE, affiliatedResource = Resource.CONNECTOR, operation = Operation.ATTRIBUTE_CALLBACK)
    public Object resourceCallback(
            Resource resource,
            String parentObjectUuid,
            RequestAttributeCallback callback
    ) throws NotFoundException, ConnectorException, ValidationException, AttributeException {
        return callbackService.resourceCallback(
                resource,
                parentObjectUuid,
                callback
        );
    }

}
