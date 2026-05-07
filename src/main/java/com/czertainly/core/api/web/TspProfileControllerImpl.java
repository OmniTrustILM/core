package com.czertainly.core.api.web;

import com.czertainly.api.exception.AlreadyExistException;
import com.czertainly.api.exception.AttributeException;
import com.czertainly.api.exception.NotFoundException;
import com.czertainly.api.interfaces.core.web.TspProfileController;
import com.czertainly.api.model.client.signing.protocols.tsp.TspProfileDto;
import com.czertainly.api.model.client.signing.protocols.tsp.TspProfileListDto;
import com.czertainly.api.model.client.signing.protocols.tsp.TspProfileRequestDto;
import com.czertainly.api.model.common.BulkActionMessageDto;
import com.czertainly.api.model.client.certificate.SearchRequestDto;
import com.czertainly.api.model.common.PaginationResponseDto;
import com.czertainly.api.model.core.search.SearchFieldDataByGroupDto;
import com.czertainly.api.model.core.auth.Resource;
import com.czertainly.api.model.core.logging.enums.Module;
import com.czertainly.api.model.core.logging.enums.Operation;
import com.czertainly.core.aop.AuditLogged;
import com.czertainly.core.auth.AuthEndpoint;
import com.czertainly.core.logging.LogResource;
import com.czertainly.core.security.authz.SecuredUUID;
import com.czertainly.core.security.authz.SecurityFilter;
import com.czertainly.core.service.TspProfileService;
import jakarta.validation.Valid;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;
import java.util.UUID;

@RestController
public class TspProfileControllerImpl implements TspProfileController {

    private final TspProfileService tspProfileService;

    @Autowired
    public TspProfileControllerImpl(TspProfileService tspProfileService) {
        this.tspProfileService = tspProfileService;
    }

    @Override
    @AuditLogged(module = Module.SIGNING, resource = Resource.SEARCH_FILTER, affiliatedResource = Resource.TSP_PROFILE, operation = Operation.LIST)
    public List<SearchFieldDataByGroupDto> getSearchableFieldInformation() {
        return tspProfileService.getSearchableFieldInformation();
    }

    @Override
    @AuthEndpoint(resourceName = Resource.TSP_PROFILE)
    @AuditLogged(module = Module.SIGNING, resource = Resource.TSP_PROFILE, operation = Operation.LIST)
    public PaginationResponseDto<TspProfileListDto> listTspProfiles(SearchRequestDto request) {
        return tspProfileService.listTspProfiles(request, SecurityFilter.create());
    }

    @Override
    @AuditLogged(module = Module.SIGNING, resource = Resource.TSP_PROFILE, operation = Operation.DETAIL)
    public TspProfileDto getTspProfile(@LogResource(uuid = true) UUID uuid) throws NotFoundException {
        return tspProfileService.getTspProfile(SecuredUUID.fromUUID(uuid));
    }

    @Override
    @AuditLogged(module = Module.SIGNING, resource = Resource.TSP_PROFILE, operation = Operation.CREATE)
    public TspProfileDto createTspProfile(@Valid TspProfileRequestDto request) throws AlreadyExistException, AttributeException, NotFoundException {
        return tspProfileService.createTspProfile(request);
    }

    @Override
    @AuditLogged(module = Module.SIGNING, resource = Resource.TSP_PROFILE, operation = Operation.UPDATE)
    public TspProfileDto updateTspProfile(@LogResource(uuid = true) UUID uuid, @Valid TspProfileRequestDto request) throws AlreadyExistException, AttributeException, NotFoundException {
        return tspProfileService.updateTspProfile(SecuredUUID.fromUUID(uuid), request);
    }

    @Override
    @AuditLogged(module = Module.SIGNING, resource = Resource.TSP_PROFILE, operation = Operation.DELETE)
    public void deleteTspProfile(@LogResource(uuid = true) UUID uuid) throws NotFoundException {
        tspProfileService.deleteTspProfile(SecuredUUID.fromUUID(uuid));
    }

    @Override
    @AuditLogged(module = Module.SIGNING, resource = Resource.TSP_PROFILE, operation = Operation.DELETE)
    public List<BulkActionMessageDto> bulkDeleteTspProfiles(@LogResource(uuid = true) List<UUID> uuids) {
        return tspProfileService.bulkDeleteTspProfiles(SecuredUUID.fromUuidList(uuids));
    }

    @Override
    @AuditLogged(module = Module.SIGNING, resource = Resource.TSP_PROFILE, operation = Operation.ENABLE)
    public void enableTspProfile(@LogResource(uuid = true) UUID uuid) throws NotFoundException {
        tspProfileService.enableTspProfile(SecuredUUID.fromUUID(uuid));
    }

    @Override
    @AuditLogged(module = Module.SIGNING, resource = Resource.TSP_PROFILE, operation = Operation.ENABLE)
    public List<BulkActionMessageDto> bulkEnableTspProfiles(@LogResource(uuid = true) List<UUID> uuids) {
        return tspProfileService.bulkEnableTspProfiles(SecuredUUID.fromUuidList(uuids));
    }

    @Override
    @AuditLogged(module = Module.SIGNING, resource = Resource.TSP_PROFILE, operation = Operation.DISABLE)
    public void disableTspProfile(@LogResource(uuid = true) UUID uuid) throws NotFoundException {
        tspProfileService.disableTspProfile(SecuredUUID.fromUUID(uuid));
    }

    @Override
    @AuditLogged(module = Module.SIGNING, resource = Resource.TSP_PROFILE, operation = Operation.DISABLE)
    public List<BulkActionMessageDto> bulkDisableTspProfiles(@LogResource(uuid = true) List<UUID> uuids) {
        return tspProfileService.bulkDisableTspProfiles(SecuredUUID.fromUuidList(uuids));
    }
}
