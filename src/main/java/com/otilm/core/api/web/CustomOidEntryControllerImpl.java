package com.otilm.core.api.web;

import com.otilm.api.exception.NotFoundException;
import com.otilm.api.interfaces.core.web.CustomOidEntryController;
import com.otilm.api.model.client.certificate.SearchRequestDto;
import com.otilm.api.model.core.auth.Resource;
import com.otilm.api.model.core.logging.enums.Module;
import com.otilm.api.model.core.logging.enums.Operation;
import com.otilm.api.model.core.oid.*;
import com.otilm.api.model.core.search.SearchFieldDataByGroupDto;
import com.otilm.core.aop.AuditLogged;
import com.otilm.core.service.CustomOidEntryExternalService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;

import java.util.List;

@Controller
public class CustomOidEntryControllerImpl implements CustomOidEntryController {

    private CustomOidEntryExternalService customOidEntryService;

    @Autowired
    public void setOidEntryService(CustomOidEntryExternalService customOidEntryService) {
        this.customOidEntryService = customOidEntryService;
    }

    @Override
    @AuditLogged(module = Module.CORE, resource = Resource.OID, operation = Operation.CREATE)
    public CustomOidEntryDetailResponseDto createCustomOidEntry(CustomOidEntryRequestDto requestDto) {
        return customOidEntryService.createCustomOidEntry(requestDto);
    }

    @Override
    @AuditLogged(module = Module.CORE, resource = Resource.OID, operation = Operation.DETAIL)
    public CustomOidEntryDetailResponseDto getCustomOidEntry(String oid) throws NotFoundException {
        return customOidEntryService.getCustomOidEntry(oid);
    }

    @Override
    @AuditLogged(module = Module.CORE, resource = Resource.OID, operation = Operation.UPDATE)
    public CustomOidEntryDetailResponseDto editCustomOidEntry(String oid, CustomOidEntryUpdateRequestDto updateDto) throws NotFoundException {
        return customOidEntryService.editCustomOidEntry(oid, updateDto);
    }

    @Override
    @AuditLogged(module = Module.CORE, resource = Resource.OID, operation = Operation.DELETE)
    public void deleteCustomOidEntry(String oid) throws NotFoundException {
        customOidEntryService.deleteCustomOidEntry(oid);
    }

    @Override
    @AuditLogged(module = Module.CORE, resource = Resource.OID, operation = Operation.DELETE)
    public void bulkDeleteCustomOidEntry(List<String> oids) {
        customOidEntryService.bulkDeleteCustomOidEntry(oids);
    }

    @Override
    @AuditLogged(module = Module.CORE, resource = Resource.OID, operation = Operation.LIST)
    public CustomOidEntryListResponseDto listCustomOidEntries(SearchRequestDto searchRequestDto) {
        return customOidEntryService.listCustomOidEntries(searchRequestDto);
    }

    @Override
    @AuditLogged(module = Module.CORE, resource = Resource.OID, operation = Operation.LIST)
    public List<CustomOidEntryDetailResponseDto> listSystemOidEntries(OidCategory category) {
        return customOidEntryService.listSystemOidEntries(category);
    }

    @Override
    @AuditLogged(module = Module.CORE, resource = Resource.SEARCH_FILTER, affiliatedResource = Resource.OID, operation = Operation.LIST)
    public List<SearchFieldDataByGroupDto> getSearchableInformation() {
        return customOidEntryService.getSearchableFieldInformation();
    }
}
