package com.czertainly.core.api.web;

import com.otilm.api.exception.*;
import com.otilm.api.interfaces.core.web.ScepProfileController;
import com.otilm.api.model.client.scep.ScepProfileEditRequestDto;
import com.otilm.api.model.client.scep.ScepProfileRequestDto;
import com.otilm.api.model.common.BulkActionMessageDto;
import com.otilm.api.model.core.certificate.CertificateDto;
import com.otilm.api.model.core.logging.enums.Module;
import com.otilm.api.model.core.logging.enums.Operation;
import com.otilm.api.model.core.scep.ScepProfileDto;
import com.otilm.api.model.core.auth.Resource;
import com.otilm.api.model.core.scep.ScepProfileDetailDto;
import com.czertainly.core.aop.AuditLogged;
import com.czertainly.core.auth.AuthEndpoint;
import com.czertainly.core.logging.LogResource;
import com.czertainly.core.security.authz.SecuredUUID;
import com.czertainly.core.security.authz.SecurityFilter;
import com.czertainly.core.service.ScepProfileService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.servlet.support.ServletUriComponentsBuilder;

import java.net.URI;
import java.util.List;

@RestController
public class ScepProfileControllerImpl implements ScepProfileController {

    private ScepProfileService scepProfileService;

    @Autowired
    public void setScepProfileService(ScepProfileService scepProfileService) {
        this.scepProfileService = scepProfileService;
    }

    @Override
    @AuthEndpoint(resourceName = Resource.SCEP_PROFILE)
    @AuditLogged(module = Module.PROTOCOLS, resource = Resource.SCEP_PROFILE, operation = Operation.LIST)
    public List<ScepProfileDto> listScepProfiles() {
        return scepProfileService.listScepProfile(SecurityFilter.create());
    }

    @Override
    @AuditLogged(module = Module.PROTOCOLS, resource = Resource.SCEP_PROFILE, operation = Operation.DETAIL)
    public ScepProfileDetailDto getScepProfile(@LogResource(uuid = true) String uuid) throws NotFoundException {
        return scepProfileService.getScepProfile(SecuredUUID.fromString(uuid));
    }

    @Override
    @AuditLogged(module = Module.PROTOCOLS, resource = Resource.SCEP_PROFILE, operation = Operation.CREATE)
    public ResponseEntity<ScepProfileDetailDto> createScepProfile(ScepProfileRequestDto request) throws AlreadyExistException, ValidationException, ConnectorException, AttributeException, NotFoundException {
        ScepProfileDetailDto scepProfile = scepProfileService.createScepProfile(request);
        URI location = ServletUriComponentsBuilder.fromCurrentRequest().path("/{uuid}")
                .buildAndExpand(scepProfile.getUuid()).toUri();
        return ResponseEntity.created(location).body(scepProfile);
    }

    @Override
    @AuditLogged(module = Module.PROTOCOLS, resource = Resource.SCEP_PROFILE, operation = Operation.UPDATE)
    public ScepProfileDetailDto editScepProfile(@LogResource(uuid = true) String uuid, ScepProfileEditRequestDto request) throws ConnectorException, AttributeException, NotFoundException {
        return scepProfileService.editScepProfile(SecuredUUID.fromString(uuid), request);
    }

    @Override
    @AuditLogged(module = Module.PROTOCOLS, resource = Resource.SCEP_PROFILE, operation = Operation.DELETE)
    public void deleteScepProfile(@LogResource(uuid = true) String uuid) throws NotFoundException, ValidationException {
        scepProfileService.deleteScepProfile(SecuredUUID.fromString(uuid));
    }

    @Override
    @AuditLogged(module = Module.PROTOCOLS, resource = Resource.SCEP_PROFILE, operation = Operation.DELETE)
    public List<BulkActionMessageDto> bulkDeleteScepProfile(@LogResource(uuid = true) List<String> uuids) {
        return scepProfileService.bulkDeleteScepProfile(SecuredUUID.fromList(uuids));
    }

    @Override
    @AuditLogged(module = Module.PROTOCOLS, resource = Resource.SCEP_PROFILE, operation = Operation.FORCE_DELETE)
    public List<BulkActionMessageDto> forceDeleteScepProfiles(@LogResource(uuid = true) List<String> uuids) {
        return scepProfileService.bulkForceRemoveScepProfiles(SecuredUUID.fromList(uuids));
    }

    @Override
    @AuditLogged(module = Module.PROTOCOLS, resource = Resource.SCEP_PROFILE, operation = Operation.ENABLE)
    public void enableScepProfile(@LogResource(uuid = true) String uuid) throws NotFoundException {
        scepProfileService.enableScepProfile(SecuredUUID.fromString(uuid));
    }

    @Override
    @AuditLogged(module = Module.PROTOCOLS, resource = Resource.SCEP_PROFILE, operation = Operation.ENABLE)
    public void bulkEnableScepProfile(@LogResource(uuid = true) List<String> uuids) {
        scepProfileService.bulkEnableScepProfile(SecuredUUID.fromList(uuids));
    }

    @Override
    @AuditLogged(module = Module.PROTOCOLS, resource = Resource.SCEP_PROFILE, operation = Operation.DISABLE)
    public void disableScepProfile(@LogResource(uuid = true) String uuid) throws NotFoundException {
        scepProfileService.disableScepProfile(SecuredUUID.fromString(uuid));
    }

    @Override
    @AuditLogged(module = Module.PROTOCOLS, resource = Resource.SCEP_PROFILE, operation = Operation.DISABLE)
    public void bulkDisableScepProfile(@LogResource(uuid = true) List<String> uuids) {
        scepProfileService.bulkDisableScepProfile(SecuredUUID.fromList(uuids));
    }

    @Override
    @AuditLogged(module = Module.PROTOCOLS, resource = Resource.SCEP_PROFILE, affiliatedResource = Resource.RA_PROFILE, operation = Operation.UPDATE_PROTOCOL_ISSUE_PROFILE)
    public void updateRaProfile(@LogResource(uuid = true) String uuid, @LogResource(uuid = true, affiliated = true) String raProfileUuid) throws NotFoundException {
        scepProfileService.updateRaProfile(SecuredUUID.fromString(uuid), raProfileUuid);
    }

    @Override
    @AuditLogged(module = Module.PROTOCOLS, resource = Resource.SCEP_PROFILE, affiliatedResource = Resource.CERTIFICATE, operation = Operation.LIST_PROTOCOL_CERTIFICATES)
    public List<CertificateDto> listScepCaCertificates(boolean intuneEnabled) {
        return scepProfileService.listScepCaCertificates(intuneEnabled);
    }
}
