package com.otilm.core.api.web;

import java.util.List;
import java.util.UUID;

import com.otilm.api.model.common.BulkActionMessageDto;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.RestController;

import com.otilm.api.exception.AlreadyExistException;
import com.otilm.api.exception.NotFoundException;
import com.otilm.api.exception.ValidationException;
import com.otilm.api.interfaces.core.web.CbomController;
import com.otilm.api.model.client.certificate.SearchRequestDto;
import com.otilm.api.model.common.PaginationResponseDto;
import com.otilm.api.model.core.auth.Resource;
import com.otilm.api.model.core.cbom.CbomDetailDto;
import com.otilm.api.model.core.cbom.CbomDto;
import com.otilm.api.model.core.cbom.CbomUploadRequestDto;
import com.otilm.api.model.core.logging.enums.Operation;
import com.otilm.api.model.core.search.SearchFieldDataByGroupDto;
import com.otilm.api.model.core.logging.enums.Module;
import com.otilm.core.aop.AuditLogged;
import com.otilm.core.logging.LogResource;
import com.otilm.api.exception.CbomRepositoryException;
import com.otilm.core.security.authz.SecuredUUID;
import com.otilm.core.security.authz.SecurityFilter;
import com.otilm.core.service.CbomService;

@RestController
public class CbomControllerImpl implements CbomController {

    private CbomService cbomService;

    @Autowired
    public void setCbomService(CbomService cbomService) {
        this.cbomService = cbomService;
    }

    @Override
    @AuditLogged(
        module = Module.CORE,
        resource = Resource.CBOM,
        operation = Operation.LIST)
    public PaginationResponseDto<CbomDto> listCboms(SearchRequestDto requestDto) {
        return cbomService.listCboms(SecurityFilter.create(), requestDto);
    }

    @Override
    @AuditLogged(
        module = Module.CORE,
        resource = Resource.CBOM,
        operation = Operation.DETAIL)
    public CbomDetailDto getCbomDetail(@LogResource(uuid = true) UUID uuid) throws NotFoundException, CbomRepositoryException {
        return cbomService.getCbomDetail(SecuredUUID.fromUUID(uuid));
    }

    @Override
    @AuditLogged(
        module = Module.CORE,
        resource = Resource.CBOM,
        operation = Operation.LIST_VERSIONS)
    public List<CbomDto> listCbomVersions(@LogResource(uuid = true) UUID uuid) throws NotFoundException {
        return cbomService.getCbomVersions(SecuredUUID.fromUUID(uuid));
    }

    @Override
    @AuditLogged(
        module = Module.CORE,
        resource = Resource.CBOM,
        operation = Operation.CREATE)
    public CbomDto uploadCbom(CbomUploadRequestDto request) throws ValidationException, AlreadyExistException, CbomRepositoryException {
        return cbomService.createCbom(request);
    }

    @Override
    @AuditLogged(module = Module.CORE, resource = Resource.CBOM, operation = Operation.DELETE)
    public void deleteCbom(@LogResource(uuid = true) UUID uuid) throws NotFoundException {
        cbomService.deleteCbom(uuid);
    }

    @Override
    @AuditLogged(module = Module.CORE, resource = Resource.CBOM, operation = Operation.DELETE)
    public List<BulkActionMessageDto> bulkDeleteCbom(@LogResource(uuid = true) List<UUID> uuids) {
        return cbomService.bulkDeleteCbom(uuids);
    }

    @AuditLogged(
        module = Module.CORE,
        resource = Resource.CBOM,
        operation = Operation.SYNC)
    public void sync() throws CbomRepositoryException {
        cbomService.syncAuthorized();
    }

    @Override
    @AuditLogged(
        module = Module.CORE,
        resource = Resource.SEARCH_FILTER,
        affiliatedResource = Resource.CBOM,
        operation = Operation.LIST
    )
    public List<SearchFieldDataByGroupDto> getSearchableFieldInformation(){
        return cbomService.getSearchableFieldInformationByGroup();
    }
}
