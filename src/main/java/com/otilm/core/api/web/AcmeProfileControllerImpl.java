package com.otilm.core.api.web;

import com.otilm.api.exception.*;
import com.otilm.api.interfaces.core.web.AcmeProfileController;
import com.otilm.api.model.client.acme.AcmeProfileEditRequestDto;
import com.otilm.api.model.client.acme.AcmeProfileRequestDto;
import com.otilm.api.model.common.BulkActionMessageDto;
import com.otilm.api.model.common.UuidDto;
import com.otilm.api.model.core.acme.AcmeProfileDto;
import com.otilm.api.model.core.acme.AcmeProfileListDto;
import com.otilm.api.model.core.auth.Resource;
import com.otilm.api.model.core.logging.enums.Module;
import com.otilm.api.model.core.logging.enums.Operation;
import com.otilm.core.aop.AuditLogged;
import com.otilm.core.auth.AuthEndpoint;
import com.otilm.core.logging.LogResource;
import com.otilm.core.security.authz.SecuredUUID;
import com.otilm.core.security.authz.SecurityFilter;
import com.otilm.core.service.AcmeProfileExternalService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.servlet.support.ServletUriComponentsBuilder;

import java.net.URI;
import java.util.List;

@RestController
public class AcmeProfileControllerImpl implements AcmeProfileController {

    private AcmeProfileExternalService acmeProfileService;

    @Autowired
    public void setAcmeProfileService(AcmeProfileExternalService acmeProfileService) {
        this.acmeProfileService = acmeProfileService;
    }

    @Override
    @AuthEndpoint(resourceName = Resource.ACME_PROFILE)
    @AuditLogged(module = Module.PROTOCOLS, resource = Resource.ACME_PROFILE, operation = Operation.LIST)
    public List<AcmeProfileListDto> listAcmeProfiles() {
        return acmeProfileService.listAcmeProfile(SecurityFilter.create());
    }

    @Override
    @AuditLogged(module = Module.PROTOCOLS, resource = Resource.ACME_PROFILE, operation = Operation.DETAIL)
    public AcmeProfileDto getAcmeProfile(@LogResource(uuid = true) String uuid) throws NotFoundException {
        return acmeProfileService.getAcmeProfile(SecuredUUID.fromString(uuid));
    }

    @Override
    @AuditLogged(module = Module.PROTOCOLS, resource = Resource.ACME_PROFILE, operation = Operation.CREATE)
    public ResponseEntity<UuidDto> createAcmeProfile(AcmeProfileRequestDto request) throws AlreadyExistException, ValidationException, ConnectorException, AttributeException, NotFoundException {
        AcmeProfileDto acmeProfile = acmeProfileService.createAcmeProfile(request);
        URI location = ServletUriComponentsBuilder.fromCurrentRequest().path("/{uuid}")
                .buildAndExpand(acmeProfile.getUuid()).toUri();

        UuidDto dto = new UuidDto();
        dto.setUuid(acmeProfile.getUuid());
        return ResponseEntity.created(location).body(dto);
    }

    @Override
    @AuditLogged(module = Module.PROTOCOLS, resource = Resource.ACME_PROFILE, operation = Operation.UPDATE)
    public AcmeProfileDto editAcmeProfile(@LogResource(uuid = true) String uuid, AcmeProfileEditRequestDto request) throws ConnectorException, AttributeException, NotFoundException {
        return acmeProfileService.editAcmeProfile(SecuredUUID.fromString(uuid), request);
    }

    @Override
    @AuditLogged(module = Module.PROTOCOLS, resource = Resource.ACME_PROFILE, operation = Operation.DELETE)
    public void deleteAcmeProfile(@LogResource(uuid = true) String uuid) throws NotFoundException, ValidationException {
        acmeProfileService.deleteAcmeProfile(SecuredUUID.fromString(uuid));
    }

    @Override
    @AuditLogged(module = Module.PROTOCOLS, resource = Resource.ACME_PROFILE, operation = Operation.ENABLE)
    public void enableAcmeProfile(@LogResource(uuid = true) String uuid) throws NotFoundException {
        acmeProfileService.enableAcmeProfile(SecuredUUID.fromString(uuid));
    }

    @Override
    @AuditLogged(module = Module.PROTOCOLS, resource = Resource.ACME_PROFILE, operation = Operation.DISABLE)
    public void disableAcmeProfile(@LogResource(uuid = true) String uuid) throws NotFoundException {
        acmeProfileService.disableAcmeProfile(SecuredUUID.fromString(uuid));
    }

    @Override
    @AuditLogged(module = Module.PROTOCOLS, resource = Resource.ACME_PROFILE, operation = Operation.ENABLE)
    public void bulkEnableAcmeProfile(@LogResource(uuid = true) List<String> uuids) {
        acmeProfileService.bulkEnableAcmeProfile(SecuredUUID.fromList(uuids));
    }

    @Override
    @AuditLogged(module = Module.PROTOCOLS, resource = Resource.ACME_PROFILE, operation = Operation.DISABLE)
    public void bulkDisableAcmeProfile(@LogResource(uuid = true) List<String> uuids) {
        acmeProfileService.bulkDisableAcmeProfile(SecuredUUID.fromList(uuids));
    }

    @Override
    @AuditLogged(module = Module.PROTOCOLS, resource = Resource.ACME_PROFILE, operation = Operation.DELETE)
    public List<BulkActionMessageDto> bulkDeleteAcmeProfile(@LogResource(uuid = true) List<String> uuids) {
        return acmeProfileService.bulkDeleteAcmeProfile(SecuredUUID.fromList(uuids));
    }

    @Override
    @AuditLogged(module = Module.PROTOCOLS, resource = Resource.ACME_PROFILE, operation = Operation.FORCE_DELETE)
    public List<BulkActionMessageDto> forceDeleteACMEProfiles(@LogResource(uuid = true) List<String> uuids) throws ValidationException {
        return acmeProfileService.bulkForceRemoveACMEProfiles(SecuredUUID.fromList(uuids));
    }

    @Override
    @AuditLogged(module = Module.PROTOCOLS, resource = Resource.ACME_PROFILE, affiliatedResource = Resource.RA_PROFILE, operation = Operation.UPDATE_PROTOCOL_ISSUE_PROFILE)
    public void updateRaProfile(@LogResource(uuid = true) String uuid, @LogResource(uuid = true, affiliated = true) String raProfileUuid) throws NotFoundException {
        acmeProfileService.updateRaProfile(SecuredUUID.fromString(uuid), raProfileUuid);
    }
}
