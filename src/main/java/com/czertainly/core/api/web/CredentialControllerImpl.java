package com.czertainly.core.api.web;

import com.otilm.api.exception.*;
import com.otilm.api.interfaces.core.web.CredentialController;
import com.otilm.api.model.client.credential.CredentialRequestDto;
import com.otilm.api.model.client.credential.CredentialUpdateRequestDto;
import com.otilm.api.model.common.UuidDto;
import com.otilm.api.model.core.auth.Resource;
import com.otilm.api.model.core.credential.CredentialDto;
import com.otilm.api.model.core.logging.enums.Module;
import com.otilm.api.model.core.logging.enums.Operation;
import com.czertainly.core.aop.AuditLogged;
import com.czertainly.core.auth.AuthEndpoint;
import com.czertainly.core.logging.LogResource;
import com.czertainly.core.security.authz.SecuredUUID;
import com.czertainly.core.security.authz.SecurityFilter;
import com.czertainly.core.service.CredentialService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.servlet.support.ServletUriComponentsBuilder;

import java.net.URI;
import java.util.List;

@RestController
public class CredentialControllerImpl implements CredentialController {

    private CredentialService credentialService;

    @Autowired
    public void setCredentialService(CredentialService credentialService) {
        this.credentialService = credentialService;
    }

    @Override
    @AuthEndpoint(resourceName = Resource.CREDENTIAL)
    @AuditLogged(module = Module.CORE, resource = Resource.CREDENTIAL, operation = Operation.LIST)
    public List<CredentialDto> listCredentials() {
        return credentialService.listCredentials(SecurityFilter.create());
    }

    @Override
    @AuditLogged(module = Module.CORE, resource = Resource.CREDENTIAL, operation = Operation.DETAIL)
    public CredentialDto getCredential(@LogResource(uuid = true) @PathVariable String uuid) throws NotFoundException {
        return credentialService.getCredential(SecuredUUID.fromString(uuid));
    }

    @Override
    @AuditLogged(module = Module.CORE, resource = Resource.CREDENTIAL, operation = Operation.CREATE)
    public ResponseEntity<?> createCredential(@RequestBody CredentialRequestDto request) throws AlreadyExistException, NotFoundException, ConnectorException, AttributeException {
        CredentialDto credentialDto = credentialService.createCredential(request);

        URI location = ServletUriComponentsBuilder
                .fromCurrentRequest()
                .path("/{uuid}")
                .buildAndExpand(credentialDto.getUuid())
                .toUri();

        UuidDto dto = new UuidDto();
        dto.setUuid(credentialDto.getUuid());

        return ResponseEntity.created(location).body(dto);
    }

    @Override
    @AuditLogged(module = Module.CORE, resource = Resource.CREDENTIAL, operation = Operation.UPDATE)
    public CredentialDto editCredential(@LogResource(uuid = true) @PathVariable String uuid, @RequestBody CredentialUpdateRequestDto request) throws NotFoundException, ConnectorException, AttributeException {
        return credentialService.editCredential(SecuredUUID.fromString(uuid), request);
    }

    @Override
    @AuditLogged(module = Module.CORE, resource = Resource.CREDENTIAL, operation = Operation.DELETE)
    public void deleteCredential(@LogResource(uuid = true) @PathVariable String uuid) throws NotFoundException {
        credentialService.deleteCredential(SecuredUUID.fromString(uuid));
    }

    @Override
    @AuditLogged(module = Module.CORE, resource = Resource.CREDENTIAL, operation = Operation.ENABLE)
    public void enableCredential(@LogResource(uuid = true) @PathVariable String uuid) throws NotFoundException {
        credentialService.enableCredential(SecuredUUID.fromString(uuid));
    }

    @Override
    @AuditLogged(module = Module.CORE, resource = Resource.CREDENTIAL, operation = Operation.DISABLE)
    public void disableCredential(@LogResource(uuid = true) @PathVariable String uuid) throws NotFoundException {
        credentialService.disableCredential(SecuredUUID.fromString(uuid));
    }

    @Override
    @AuditLogged(module = Module.CORE, resource = Resource.CREDENTIAL, operation = Operation.DELETE)
    public void bulkDeleteCredential(@LogResource(uuid = true) List<String> uuids) throws NotFoundException, ValidationException {
        credentialService.bulkDeleteCredential(SecuredUUID.fromList(uuids));
    }
}
