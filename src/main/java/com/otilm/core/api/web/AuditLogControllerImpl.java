package com.otilm.core.api.web;

import com.otilm.api.interfaces.core.web.AuditLogController;
import com.otilm.api.model.client.certificate.SearchFilterRequestDto;
import com.otilm.api.model.client.certificate.SearchRequestDto;
import com.otilm.api.model.core.audit.AuditLogResponseDto;
import com.otilm.api.model.core.audit.ExportResultDto;
import com.otilm.api.model.core.auth.Resource;
import com.otilm.api.model.core.logging.enums.Module;
import com.otilm.api.model.core.logging.enums.Operation;
import com.otilm.api.model.core.search.SearchFieldDataByGroupDto;
import com.otilm.core.aop.AuditLogged;
import com.otilm.core.service.AuditLogExternalService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.core.io.ByteArrayResource;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.RestController;
import java.util.List;

@RestController
public class AuditLogControllerImpl implements AuditLogController {

    private AuditLogExternalService auditLogService;

    @Autowired
    public void setAuditLogService(AuditLogExternalService auditLogService) {
        this.auditLogService = auditLogService;
    }

    @Override
    @AuditLogged(module = Module.CORE, resource = Resource.AUDIT_LOG, operation = Operation.LIST)
    public AuditLogResponseDto listAuditLogs(final SearchRequestDto requestDto) {
        return auditLogService.listAuditLogs(requestDto);
    }

    @Override
    @AuditLogged(module = Module.CORE, resource = Resource.AUDIT_LOG, operation = Operation.EXPORT)
    public ResponseEntity<org.springframework.core.io.Resource> exportAuditLogs(final List<SearchFilterRequestDto> filters) {
        ExportResultDto export = auditLogService.exportAuditLogs(filters);

        return ResponseEntity.ok()
                .contentType(MediaType.APPLICATION_OCTET_STREAM)
                .contentLength(export.getFileContent().length)
                .header(HttpHeaders.CONTENT_DISPOSITION, "attachment; filename=" + export.getFileName())
                .body(new ByteArrayResource(export.getFileContent()));
    }

    @Override
    @AuditLogged(module = Module.CORE, resource = Resource.AUDIT_LOG, operation = Operation.DELETE)
    public void purgeAuditLogs(final List<SearchFilterRequestDto> filters) {
        auditLogService.purgeAuditLogs(filters);
    }

    @Override
    @AuditLogged(module = Module.CORE, resource = Resource.SEARCH_FILTER, affiliatedResource = Resource.AUDIT_LOG, operation = Operation.LIST)
    public List<SearchFieldDataByGroupDto> getSearchableFieldInformation() {
        return auditLogService.getSearchableFieldInformationByGroup();
    }
}
