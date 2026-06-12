package com.otilm.core.api.web;

import com.otilm.api.exception.AlreadyExistException;
import com.otilm.api.exception.AttributeException;
import com.otilm.api.exception.ConnectorCommunicationException;
import com.otilm.api.exception.NotFoundException;
import com.otilm.api.interfaces.core.web.TspProfileBasicCredentialController;
import com.otilm.api.model.client.signing.protocols.tsp.TspBasicCredentialDto;
import com.otilm.api.model.client.signing.protocols.tsp.TspBasicCredentialRequestDto;
import com.otilm.api.model.core.auth.Resource;
import com.otilm.api.model.core.logging.enums.Module;
import com.otilm.api.model.core.logging.enums.Operation;
import com.otilm.core.aop.AuditLogged;
import com.otilm.core.logging.LogResource;
import com.otilm.core.security.authz.SecuredParentUUID;
import com.otilm.core.security.authz.SecuredUUID;
import com.otilm.core.service.TspProfileBasicCredentialService;
import jakarta.validation.Valid;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;
import java.util.UUID;

@RestController
public class TspProfileBasicCredentialControllerImpl implements TspProfileBasicCredentialController {

    private TspProfileBasicCredentialService service;

    @Autowired
    public void setService(TspProfileBasicCredentialService service) {
        this.service = service;
    }

    @Override
    @AuditLogged(module = Module.SIGNING, resource = Resource.TSP_PROFILE_BASIC_CREDENTIAL, affiliatedResource = Resource.TSP_PROFILE, operation = Operation.LIST)
    public List<TspBasicCredentialDto> list(@LogResource(uuid = true, affiliated = true) UUID tspProfileUuid) throws NotFoundException {
        return service.list(SecuredParentUUID.fromUUID(tspProfileUuid));
    }

    @Override
    @AuditLogged(module = Module.SIGNING, resource = Resource.TSP_PROFILE_BASIC_CREDENTIAL, affiliatedResource = Resource.TSP_PROFILE, operation = Operation.DETAIL)
    public TspBasicCredentialDto get(@LogResource(uuid = true, affiliated = true) UUID tspProfileUuid, @LogResource(uuid = true) UUID uuid) throws NotFoundException {
        return service.get(SecuredParentUUID.fromUUID(tspProfileUuid), SecuredUUID.fromUUID(uuid));
    }

    @Override
    @AuditLogged(module = Module.SIGNING, resource = Resource.TSP_PROFILE_BASIC_CREDENTIAL, affiliatedResource = Resource.TSP_PROFILE, operation = Operation.CREATE)
    public TspBasicCredentialDto create(@LogResource(uuid = true, affiliated = true) UUID tspProfileUuid, @Valid TspBasicCredentialRequestDto request) throws AlreadyExistException, AttributeException, ConnectorCommunicationException, NotFoundException {
        return service.create(SecuredParentUUID.fromUUID(tspProfileUuid), request);
    }

    @Override
    @AuditLogged(module = Module.SIGNING, resource = Resource.TSP_PROFILE_BASIC_CREDENTIAL, affiliatedResource = Resource.TSP_PROFILE, operation = Operation.UPDATE)
    public TspBasicCredentialDto update(@LogResource(uuid = true, affiliated = true) UUID tspProfileUuid, @LogResource(uuid = true) UUID uuid, @Valid TspBasicCredentialRequestDto request) throws AlreadyExistException, AttributeException, ConnectorCommunicationException, NotFoundException {
        return service.update(SecuredParentUUID.fromUUID(tspProfileUuid), SecuredUUID.fromUUID(uuid), request);
    }

    @Override
    @AuditLogged(module = Module.SIGNING, resource = Resource.TSP_PROFILE_BASIC_CREDENTIAL, affiliatedResource = Resource.TSP_PROFILE, operation = Operation.DELETE)
    public void delete(@LogResource(uuid = true, affiliated = true) UUID tspProfileUuid, @LogResource(uuid = true) UUID uuid) throws AttributeException, ConnectorCommunicationException, NotFoundException {
        service.delete(SecuredParentUUID.fromUUID(tspProfileUuid), SecuredUUID.fromUUID(uuid));
    }
}
