package com.otilm.core.api.web;

import com.otilm.api.exception.AlreadyExistException;
import com.otilm.api.exception.AttributeException;
import com.otilm.api.exception.ConnectorException;
import com.otilm.api.exception.NotFoundException;
import com.otilm.api.interfaces.core.web.EstProfileController;
import com.otilm.api.model.client.est.EstProfileEditRequestDto;
import com.otilm.api.model.client.est.EstProfileRequestDto;
import com.otilm.api.model.common.BulkActionMessageDto;
import com.otilm.api.model.core.auth.Resource;
import com.otilm.api.model.core.est.EstProfileDetailDto;
import com.otilm.api.model.core.est.EstProfileDto;
import com.otilm.api.model.core.logging.enums.Module;
import com.otilm.api.model.core.logging.enums.Operation;
import com.otilm.core.aop.AuditLogged;
import com.otilm.core.auth.AuthEndpoint;
import com.otilm.core.logging.LogResource;
import com.otilm.core.security.authz.SecuredUUID;
import com.otilm.core.security.authz.SecurityFilter;
import com.otilm.core.service.EstProfileExternalService;
import com.otilm.core.util.EstProtocolUrlFactory;
import java.util.List;
import java.util.UUID;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class EstProfileControllerImpl implements EstProfileController {

    private final EstProfileExternalService estProfileService;

    public EstProfileControllerImpl(EstProfileExternalService estProfileService) {
        this.estProfileService = estProfileService;
    }

    @Override
    @AuthEndpoint(resourceName = Resource.EST_PROFILE)
    @AuditLogged(module = Module.PROTOCOLS, resource = Resource.EST_PROFILE, operation = Operation.LIST)
    public List<EstProfileDto> listEstProfiles() {
        return estProfileService.listEstProfiles(SecurityFilter.create(), EstProtocolUrlFactory.currentOrigin());
    }

    @Override
    @AuditLogged(module = Module.PROTOCOLS, resource = Resource.EST_PROFILE, operation = Operation.DETAIL)
    public EstProfileDetailDto getEstProfile(@LogResource(uuid = true) UUID uuid) throws NotFoundException {
        return estProfileService.getEstProfile(SecuredUUID.fromUUID(uuid), EstProtocolUrlFactory.currentOrigin());
    }

    @Override
    @AuditLogged(module = Module.PROTOCOLS, resource = Resource.EST_PROFILE, operation = Operation.CREATE)
    public EstProfileDetailDto createEstProfile(EstProfileRequestDto request)
            throws AlreadyExistException, ConnectorException, AttributeException, NotFoundException {
        return estProfileService.createEstProfile(request, EstProtocolUrlFactory.currentOrigin());
    }

    @Override
    @AuditLogged(module = Module.PROTOCOLS, resource = Resource.EST_PROFILE, operation = Operation.UPDATE)
    public EstProfileDetailDto updateEstProfile(@LogResource(uuid = true) UUID uuid, EstProfileEditRequestDto request)
            throws ConnectorException, AttributeException, NotFoundException {
        return estProfileService
                .updateEstProfile(SecuredUUID.fromUUID(uuid), request, EstProtocolUrlFactory.currentOrigin());
    }

    @Override
    @AuditLogged(module = Module.PROTOCOLS, resource = Resource.EST_PROFILE, operation = Operation.DELETE)
    public void deleteEstProfile(@LogResource(uuid = true) UUID uuid) throws NotFoundException {
        estProfileService.deleteEstProfile(SecuredUUID.fromUUID(uuid));
    }

    @Override
    @AuditLogged(module = Module.PROTOCOLS, resource = Resource.EST_PROFILE, operation = Operation.DELETE)
    public List<BulkActionMessageDto> bulkDeleteEstProfiles(@LogResource(uuid = true) List<UUID> uuids) {
        return estProfileService.bulkDeleteEstProfiles(SecuredUUID.fromUuidList(uuids));
    }

    @Override
    @AuditLogged(module = Module.PROTOCOLS, resource = Resource.EST_PROFILE, operation = Operation.FORCE_DELETE)
    public List<BulkActionMessageDto> forceDeleteEstProfiles(@LogResource(uuid = true) List<UUID> uuids) {
        return estProfileService.forceDeleteEstProfiles(SecuredUUID.fromUuidList(uuids));
    }

    @Override
    @AuditLogged(module = Module.PROTOCOLS, resource = Resource.EST_PROFILE, operation = Operation.ENABLE)
    public void enableEstProfile(@LogResource(uuid = true) UUID uuid) throws NotFoundException {
        estProfileService.enableEstProfile(SecuredUUID.fromUUID(uuid));
    }

    @Override
    @AuditLogged(module = Module.PROTOCOLS, resource = Resource.EST_PROFILE, operation = Operation.ENABLE)
    public void bulkEnableEstProfiles(@LogResource(uuid = true) List<UUID> uuids) {
        estProfileService.bulkEnableEstProfiles(SecuredUUID.fromUuidList(uuids));
    }

    @Override
    @AuditLogged(module = Module.PROTOCOLS, resource = Resource.EST_PROFILE, operation = Operation.DISABLE)
    public void disableEstProfile(@LogResource(uuid = true) UUID uuid) throws NotFoundException {
        estProfileService.disableEstProfile(SecuredUUID.fromUUID(uuid));
    }

    @Override
    @AuditLogged(module = Module.PROTOCOLS, resource = Resource.EST_PROFILE, operation = Operation.DISABLE)
    public void bulkDisableEstProfiles(@LogResource(uuid = true) List<UUID> uuids) {
        estProfileService.bulkDisableEstProfiles(SecuredUUID.fromUuidList(uuids));
    }

    @Override
    @AuditLogged(module = Module.PROTOCOLS, resource = Resource.EST_PROFILE, affiliatedResource = Resource.RA_PROFILE,
            operation = Operation.UPDATE_PROTOCOL_ISSUE_PROFILE)
    public void updateEstProfileRaProfile(@LogResource(uuid = true) UUID uuid,
            @LogResource(uuid = true, affiliated = true) UUID raProfileUuid) throws NotFoundException {
        estProfileService.updateRaProfile(SecuredUUID.fromUUID(uuid), raProfileUuid);
    }
}
