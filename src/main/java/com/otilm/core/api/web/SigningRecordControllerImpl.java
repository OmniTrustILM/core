package com.otilm.core.api.web;

import com.otilm.api.exception.NotFoundException;
import com.otilm.api.interfaces.core.web.SigningRecordController;
import com.otilm.api.model.client.certificate.SearchRequestDto;
import com.otilm.api.model.common.BulkActionMessageDto;
import com.otilm.api.model.common.PaginationResponseDto;
import com.otilm.api.model.core.search.SearchFieldDataByGroupDto;
import com.otilm.api.model.core.auth.Resource;
import com.otilm.api.model.core.logging.enums.Module;
import com.otilm.api.model.core.logging.enums.Operation;
import com.otilm.api.model.core.signing.signingrecord.SigningRecordDto;
import com.otilm.api.model.core.signing.signingrecord.SigningRecordListDto;
import com.otilm.core.aop.AuditLogged;
import com.otilm.core.auth.AuthEndpoint;
import com.otilm.core.logging.LogResource;
import com.otilm.core.security.authz.SecuredUUID;
import com.otilm.core.security.authz.SecurityFilter;
import com.otilm.core.service.SigningRecordService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;
import java.util.UUID;

@RestController
public class SigningRecordControllerImpl implements SigningRecordController {

    private final SigningRecordService signingRecordService;

    @Autowired
    public SigningRecordControllerImpl(SigningRecordService signingRecordService) {
        this.signingRecordService = signingRecordService;
    }

    @Override
    @AuthEndpoint(resourceName = Resource.SIGNING_RECORD)
    @AuditLogged(module = Module.SIGNING, resource = Resource.SIGNING_RECORD, operation = Operation.LIST)
    public List<SearchFieldDataByGroupDto> getSearchableFieldInformation() {
        return signingRecordService.getSearchableFieldInformation();
    }

    @Override
    @AuditLogged(module = Module.SIGNING, resource = Resource.SIGNING_RECORD, operation = Operation.LIST)
    public PaginationResponseDto<SigningRecordListDto> listSigningRecords(SearchRequestDto request) {
        return signingRecordService.listSigningRecords(request, SecurityFilter.create());
    }

    @Override
    @AuditLogged(module = Module.SIGNING, resource = Resource.SIGNING_RECORD, operation = Operation.DETAIL)
    public SigningRecordDto getSigningRecord(@LogResource(uuid = true) UUID uuid) throws NotFoundException {
        return signingRecordService.getSigningRecord(SecuredUUID.fromUUID(uuid));
    }

    @Override
    @AuditLogged(module = Module.SIGNING, resource = Resource.SIGNING_RECORD, operation = Operation.DELETE)
    public void deleteSigningRecord(@LogResource(uuid = true) UUID uuid) throws NotFoundException {
        signingRecordService.deleteSigningRecord(SecuredUUID.fromUUID(uuid));
    }

    @Override
    @AuditLogged(module = Module.SIGNING, resource = Resource.SIGNING_RECORD, operation = Operation.DELETE)
    public List<BulkActionMessageDto> bulkDeleteSigningRecords(@LogResource(uuid = true) List<UUID> uuids) {
        return signingRecordService.bulkDeleteSigningRecords(SecuredUUID.fromUuidList(uuids));
    }
}
