package com.otilm.core.api.web;

import com.otilm.api.exception.*;
import com.otilm.api.interfaces.core.web.AuthorityInstanceController;
import com.otilm.api.model.client.attribute.RequestAttribute;
import com.otilm.api.model.client.authority.AuthorityInstanceRequestDto;
import com.otilm.api.model.client.authority.AuthorityInstanceUpdateRequestDto;
import com.otilm.api.model.common.BulkActionMessageDto;
import com.otilm.api.model.common.NameAndIdDto;
import com.otilm.api.model.common.UuidDto;
import com.otilm.api.model.common.attribute.common.BaseAttribute;
import com.otilm.api.model.core.auth.Resource;
import com.otilm.api.model.core.authority.AuthorityInstanceDto;
import com.otilm.api.model.core.logging.enums.Module;
import com.otilm.api.model.core.logging.enums.Operation;
import com.otilm.core.aop.AuditLogged;
import com.otilm.core.auth.AuthEndpoint;
import com.otilm.core.logging.LogResource;
import com.otilm.core.security.authz.SecuredUUID;
import com.otilm.core.security.authz.SecurityFilter;
import com.otilm.core.service.AuthorityInstanceExternalService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.servlet.support.ServletUriComponentsBuilder;

import java.net.URI;
import java.util.List;

@RestController
public class AuthorityInstanceControllerImpl implements AuthorityInstanceController {

    private AuthorityInstanceExternalService authorityInstanceService;

    @Override
    @AuthEndpoint(resourceName = Resource.AUTHORITY)
    @AuditLogged(module = Module.CERTIFICATES, resource = Resource.AUTHORITY, operation = Operation.LIST)
    public List<AuthorityInstanceDto> listAuthorityInstances() {
        return authorityInstanceService.listAuthorityInstances(SecurityFilter.create());
    }

    @Override
    @AuditLogged(module = Module.CERTIFICATES, resource = Resource.AUTHORITY, operation = Operation.DETAIL)
    public AuthorityInstanceDto getAuthorityInstance(@LogResource(uuid = true) @PathVariable String uuid) throws ConnectorException, NotFoundException {
        return authorityInstanceService.getAuthorityInstance(SecuredUUID.fromString(uuid));
    }

    @Override
    @AuditLogged(module = Module.CERTIFICATES, resource = Resource.AUTHORITY, operation = Operation.CREATE)
    public ResponseEntity<?> createAuthorityInstance(@RequestBody AuthorityInstanceRequestDto request) throws AlreadyExistException, ConnectorException, AttributeException, NotFoundException {
        AuthorityInstanceDto authorityInstance = authorityInstanceService.createAuthorityInstance(request);

        URI location = ServletUriComponentsBuilder
                .fromCurrentRequest()
                .path("/{uuid}")
                .buildAndExpand(authorityInstance.getUuid())
                .toUri();
        UuidDto dto = new UuidDto();
        dto.setUuid(authorityInstance.getUuid());
        return ResponseEntity.created(location).body(dto);
    }

    @Override
    @AuditLogged(module = Module.CERTIFICATES, resource = Resource.AUTHORITY, operation = Operation.UPDATE)
    public AuthorityInstanceDto editAuthorityInstance(@LogResource(uuid = true) @PathVariable String uuid, @RequestBody AuthorityInstanceUpdateRequestDto request) throws ConnectorException, AttributeException, NotFoundException {
        return authorityInstanceService.editAuthorityInstance(SecuredUUID.fromString(uuid), request);
    }

    @Override
    @AuditLogged(module = Module.CERTIFICATES, resource = Resource.AUTHORITY, operation = Operation.DELETE)
    public void deleteAuthorityInstance(@LogResource(uuid = true) @PathVariable String uuid) throws ConnectorException, NotFoundException {
        authorityInstanceService.deleteAuthorityInstance(SecuredUUID.fromString(uuid));
    }

    @Override
    @AuditLogged(module = Module.CERTIFICATES, resource = Resource.END_ENTITY_PROFILE, affiliatedResource = Resource.AUTHORITY, operation = Operation.LIST)
    public List<NameAndIdDto> listEntityProfiles(@LogResource(uuid = true, affiliated = true) @PathVariable String uuid) throws ConnectorException, NotFoundException {
        return authorityInstanceService.listEndEntityProfiles(SecuredUUID.fromString(uuid));
    }

    @Override
    @AuditLogged(module = Module.CERTIFICATES, resource = Resource.END_ENTITY_PROFILE, affiliatedResource = Resource.AUTHORITY, operation = Operation.LIST_CERTIFICATE_PROFILES)
    public List<NameAndIdDto> listCertificateProfiles(@LogResource(uuid = true, affiliated = true) @PathVariable String uuid, @PathVariable Integer endEntityProfileId) throws ConnectorException, NotFoundException {
        return authorityInstanceService.listCertificateProfiles(SecuredUUID.fromString(uuid), endEntityProfileId);
    }

    @Override
    @AuditLogged(module = Module.CERTIFICATES, resource = Resource.END_ENTITY_PROFILE, affiliatedResource = Resource.AUTHORITY, operation = Operation.LIST_CAS)
    public List<NameAndIdDto> listCAsInProfile(@LogResource(uuid = true, affiliated = true) @PathVariable String uuid, @PathVariable Integer endEntityProfileId) throws ConnectorException, NotFoundException {
        return authorityInstanceService.listCAsInProfile(SecuredUUID.fromString(uuid), endEntityProfileId);
    }

    @Override
    @AuditLogged(module = Module.CERTIFICATES, resource = Resource.ATTRIBUTE, name = "authority", affiliatedResource = Resource.CONNECTOR, operation = Operation.LIST_ATTRIBUTES)
    public List<BaseAttribute> listAuthorityInstanceAttributes(@LogResource(uuid = true, affiliated = true) @PathVariable("connectorUuid") String connectorUuid, @RequestParam(name = "interfaceUuid", required = false) String interfaceUuid) throws ConnectorException, NotFoundException, AttributeException {
        return authorityInstanceService.listAuthorityInstanceAttributes(SecuredUUID.fromString(connectorUuid),
                interfaceUuid != null ? SecuredUUID.fromString(interfaceUuid).getValue() : null);
    }

    @Override
    @AuditLogged(module = Module.CERTIFICATES, resource = Resource.ATTRIBUTE, name = "raProfile", affiliatedResource = Resource.AUTHORITY, operation = Operation.LIST_ATTRIBUTES)
    public List<BaseAttribute> listRAProfileAttributes(@LogResource(uuid = true, affiliated = true) @PathVariable String uuid) throws ConnectorException, NotFoundException {
        return authorityInstanceService.listRAProfileAttributes(SecuredUUID.fromString(uuid));
    }

    @Override
    @AuditLogged(module = Module.CERTIFICATES, resource = Resource.ATTRIBUTE, name = "raProfile", affiliatedResource = Resource.AUTHORITY, operation = Operation.VALIDATE_ATTRIBUTES)
    public void validateRAProfileAttributes(@PathVariable String uuid, @RequestBody List<RequestAttribute> attributes) throws ConnectorException, AttributeException, NotFoundException {
        authorityInstanceService.validateRAProfileAttributes(SecuredUUID.fromString(uuid), attributes);
    }

    @Override
    @AuditLogged(module = Module.CERTIFICATES, resource = Resource.AUTHORITY, operation = Operation.DELETE)
    public List<BulkActionMessageDto> bulkDeleteAuthorityInstance(@LogResource(uuid = true) List<String> uuids) throws ConnectorException, ValidationException {
        return authorityInstanceService.bulkDeleteAuthorityInstance(SecuredUUID.fromList(uuids));
    }

    @Override
    @AuditLogged(module = Module.CERTIFICATES, resource = Resource.AUTHORITY, operation = Operation.FORCE_DELETE)
    public List<BulkActionMessageDto> forceDeleteAuthorityInstances(@LogResource(uuid = true) List<String> uuids) throws NotFoundException, ValidationException {
        return authorityInstanceService.forceDeleteAuthorityInstance(SecuredUUID.fromList(uuids));
    }

    // SETTERs

    @Autowired
    public void setAuthorityInstanceService(AuthorityInstanceExternalService authorityInstanceService) {
        this.authorityInstanceService = authorityInstanceService;
    }

}
