package com.otilm.core.service;

import com.otilm.api.model.client.certificate.SearchFilterRequestDto;
import com.otilm.api.model.client.certificate.SearchRequestDto;
import com.otilm.api.model.core.audit.AuditLogResponseDto;
import com.otilm.api.model.core.audit.ExportResultDto;
import com.otilm.api.model.core.search.SearchFieldDataByGroupDto;

import java.util.List;

public interface AuditLogExternalService {

    /**
     *
     * @param request {@link SearchRequestDto}
     *
     * @return {@link AuditLogResponseDto}
     */
    AuditLogResponseDto listAuditLogs(final SearchRequestDto request);

    /**
     *
     * @param filters {@link SearchFilterRequestDto}
     *
     * @return {@link ExportResultDto}
     */
    ExportResultDto exportAuditLogs(final List<SearchFilterRequestDto> filters);

    /**
     * Removes the audit logs from the database
     * @param filters {@link SearchFilterRequestDto}
     */
    void purgeAuditLogs(final List<SearchFilterRequestDto> filters);

    /**
     * Get all possible field to be able to search by customer
     * @return List of {@link SearchFieldDataByGroupDto} object with definition the possible fields
     */
    List<SearchFieldDataByGroupDto> getSearchableFieldInformationByGroup();
}
