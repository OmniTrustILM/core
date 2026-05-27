package com.czertainly.core.api.web;

import com.czertainly.api.interfaces.core.web.AuditLogController;
import com.czertainly.api.model.client.certificate.SearchFilterRequestDto;
import com.czertainly.api.model.client.certificate.SearchRequestDto;
import com.czertainly.api.model.core.audit.AuditLogResponseDto;
import com.czertainly.api.model.core.audit.ExportResultDto;
import com.czertainly.api.model.core.auth.Resource;
import com.czertainly.api.model.core.logging.enums.Module;
import com.czertainly.api.model.core.logging.enums.Operation;
import com.czertainly.api.model.core.search.SearchFieldDataByGroupDto;
import com.czertainly.core.aop.AuditLogged;
import com.czertainly.core.service.AuditLogExternalService;
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
    public void setAuditLogExternalService(AuditLogExternalService auditLogService) {
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
