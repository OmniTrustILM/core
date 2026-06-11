package com.otilm.core.service.impl;

import com.otilm.api.model.client.certificate.SearchFilterRequestDto;
import com.otilm.api.model.client.certificate.SearchRequestDto;
import com.otilm.api.model.core.audit.*;
import com.otilm.api.model.core.auth.Resource;
import com.otilm.api.model.core.logging.enums.*;
import com.otilm.api.model.core.logging.enums.Module;
import com.otilm.api.model.core.logging.records.LogRecord;
import com.otilm.api.model.core.search.FilterFieldSource;
import com.otilm.api.model.core.search.SearchFieldDataByGroupDto;
import com.otilm.api.model.core.search.SearchFieldDataDto;
import com.otilm.api.model.core.settings.SettingsSection;
import com.otilm.api.model.core.settings.logging.LoggingSettingsDto;
import com.otilm.core.dao.entity.AuditLog;
import com.otilm.core.dao.entity.AuditLog_;
import com.otilm.core.dao.repository.AuditLogRepository;
import com.otilm.core.enums.FilterField;
import com.otilm.core.logging.AuditLogExportDto;
import com.otilm.core.logging.LoggerWrapper;
import com.otilm.core.logging.LoggingHelper;
import com.otilm.core.model.auth.ResourceAction;
import com.otilm.core.security.authz.ExternalAuthorization;
import com.otilm.core.security.authz.SecurityFilter;
import com.otilm.core.service.AuditLogExternalService;
import com.otilm.core.service.AuditLogInternalService;
import com.otilm.core.settings.SettingsCache;
import com.otilm.core.util.FilterPredicatesBuilder;
import com.otilm.core.util.RequestValidatorHelper;
import com.otilm.core.util.SearchHelper;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import jakarta.persistence.EntityManager;
import jakarta.persistence.PersistenceContext;
import jakarta.persistence.criteria.CriteriaBuilder;
import jakarta.persistence.criteria.CriteriaDelete;
import jakarta.persistence.criteria.CriteriaQuery;
import jakarta.persistence.criteria.Root;
import org.apache.commons.lang3.function.TriFunction;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Pageable;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

@Service
@Transactional
public class AuditLogServiceImpl implements AuditLogExternalService, AuditLogInternalService {

    private static final LoggerWrapper logger = new LoggerWrapper(AuditLogServiceImpl.class, null, null);

    private static final ObjectMapper MAPPER = new ObjectMapper();

    static {
        MAPPER.findAndRegisterModules();
        MAPPER.configure(SerializationFeature.WRITE_DATES_AS_TIMESTAMPS, false);
        MAPPER.setSerializationInclusion(JsonInclude.Include.NON_NULL);
    }

    @Value("${export.auditLog.fileName.prefix:audit-logs}")
    private String fileNamePrefix;

    private AuditLogRepository auditLogRepository;
    private ExportProcessor exportProcessor;

    @PersistenceContext
    private EntityManager entityManager;

    @Autowired
    public void setAuditLogRepository(AuditLogRepository auditLogRepository) {
        this.auditLogRepository = auditLogRepository;
    }

    @Autowired
    public void setExportProcessor(ExportProcessor exportProcessor) {
        this.exportProcessor = exportProcessor;
    }

    @Override
    @ExternalAuthorization(resource = Resource.AUDIT_LOG, action = ResourceAction.LIST)
    public AuditLogResponseDto listAuditLogs(final SearchRequestDto request) {
        RequestValidatorHelper.revalidateSearchRequestDto(request);
        final Pageable p = PageRequest.of(request.getPageNumber() - 1, request.getItemsPerPage());

        final TriFunction<Root<AuditLog>, CriteriaBuilder, CriteriaQuery<?>, jakarta.persistence.criteria.Predicate> additionalWhereClause = (root, cb, cr) -> FilterPredicatesBuilder.getFiltersPredicate(cb, cr, root, request.getFilters());
        final List<AuditLogDto> auditLogs = auditLogRepository.findUsingSecurityFilter(SecurityFilter.create(), List.of(), additionalWhereClause, p, (root, cb) -> cb.desc(root.get(AuditLog_.id)))
                .stream()
                .map(AuditLog::mapToDto).toList();
        final Long totalItems = auditLogRepository.countUsingSecurityFilter(SecurityFilter.create(), additionalWhereClause);

        AuditLogResponseDto response = new AuditLogResponseDto();
        response.setItems(auditLogs);
        response.setItemsPerPage(request.getItemsPerPage());
        response.setPageNumber(request.getPageNumber());
        response.setTotalItems(totalItems);
        response.setTotalPages((int) Math.ceil((double) totalItems / request.getItemsPerPage()));

        return response;
    }

    @Override
    @ExternalAuthorization(resource = Resource.AUDIT_LOG, action = ResourceAction.EXPORT)
    public ExportResultDto exportAuditLogs(final List<SearchFilterRequestDto> filters) {
        final TriFunction<Root<AuditLog>, CriteriaBuilder, CriteriaQuery<?>, jakarta.persistence.criteria.Predicate> additionalWhereClause = (root, cb, cr) -> FilterPredicatesBuilder.getFiltersPredicate(cb, cr, root, filters);

        final List<AuditLog> auditLogsEntities = auditLogRepository.findUsingSecurityFilter(SecurityFilter.create(), List.of(), additionalWhereClause, Pageable.ofSize(Integer.MAX_VALUE), (root, cb) -> cb.desc(root.get(AuditLog_.id)));
        final List<AuditLogExportDto> auditLogs = auditLogsEntities
                .stream()
                .map(a -> {
                    AuditLogExportDto.AuditLogExportDtoBuilder builder = AuditLogExportDto.builder();
                    builder.id(a.getId());
                    builder.version(a.getVersion());
                    builder.loggedAt(a.getLoggedAt());
                    builder.timestamp(a.getTimestamp());
                    builder.module(a.getModule());
                    builder.resource(a.getResource());
                    builder.resourceObjects(LoggingHelper.formatResourceObjectForCsv(a.getLogRecord().resource().objects()));
                    builder.affiliatedResource(a.getAffiliatedResource());
                    if (a.getLogRecord().affiliatedResource() != null) {
                        builder.affiliatedObjects(LoggingHelper.formatResourceObjectForCsv(a.getLogRecord().affiliatedResource().objects()));
                    }
                    builder.actorType(a.getActorType());
                    builder.actorAuthMethod(a.getActorAuthMethod());
                    builder.actorUuid(a.getActorUuid());
                    builder.actorName(a.getActorName());
                    if (a.getLogRecord().source() != null) {
                        builder.ipAddress(a.getLogRecord().source().ipAddress());
                        builder.userAgent(a.getLogRecord().source().userAgent());
                    }
                    builder.operation(a.getOperation());
                    builder.operationResult(a.getOperationResult());
                    builder.message(a.getMessage());

                    try {
                        builder.operationData(MAPPER.writeValueAsString(a.getLogRecord().operationData()));
                    } catch (JsonProcessingException e) {
                        builder.operationData("ERROR_SERIALIZATION");
                    }

                    try {
                        builder.additionalData(MAPPER.writeValueAsString(a.getLogRecord().additionalData()));
                    } catch (JsonProcessingException e) {
                        builder.additionalData("ERROR_SERIALIZATION");
                    }

                    return builder.build();
                }).toList();

        return exportProcessor.generateExport(fileNamePrefix, auditLogs);
    }

    @Override
    @ExternalAuthorization(resource = Resource.AUDIT_LOG, action = ResourceAction.DELETE)
    public void purgeAuditLogs(final List<SearchFilterRequestDto> filters) {
        final TriFunction<Root<AuditLog>, CriteriaBuilder, CriteriaDelete<AuditLog>, jakarta.persistence.criteria.Predicate> additionalWhereClause = (root, cb, cd) -> FilterPredicatesBuilder.getFiltersPredicate(cb, cd, root, filters);
        final Integer deletedCount = auditLogRepository.deleteUsingSecurityFilter(SecurityFilter.create(), additionalWhereClause);
        logger.getLogger().debug("Deleted {} audit logs", deletedCount);
    }

    @Override
    @ExternalAuthorization(resource = Resource.AUDIT_LOG, action = ResourceAction.LIST)
    public List<SearchFieldDataByGroupDto> getSearchableFieldInformationByGroup() {
        final List<SearchFieldDataByGroupDto> searchFieldDataByGroupDtos = new ArrayList<>();

        List<SearchFieldDataDto> fields = new ArrayList<>();
        List<FilterField> filterFields = FilterField.getEnumsForResource(Resource.AUDIT_LOG);
        for (FilterField filterField : filterFields) {
            fields.add(SearchHelper.prepareSearch(filterField));
        }

        searchFieldDataByGroupDtos.add(new SearchFieldDataByGroupDto(fields, FilterFieldSource.PROPERTY));
        return searchFieldDataByGroupDtos;
    }

    @Override
    public void log(LogRecord logRecord, AuditLogOutput output) {
        handleAuditLogging(logRecord, output);
    }

    @Override
    public void logAuthentication(Operation operation, OperationResult operationResult, String message, String authData) {
        Module module = Module.AUTH;
        Resource resource = Resource.USER;
        if (logger.isLogFiltered(true, module, resource, null)) {
            return;
        }

        Map<String, Object> additionalData = null;
        LoggingSettingsDto loggingSettings = SettingsCache.getSettings(SettingsSection.LOGGING);
        if (loggingSettings.getAuditLogs().isVerbose()) {
            additionalData = new HashMap<>();
            additionalData.put("authData", authData);
        }

        LogRecord logRecord = logger.buildLogRecord(true, module, resource, null, operation, operationResult, null, message, additionalData);
        if (LoggingHelper.isLogFilteredBasedOnModuleAndResource(true, logRecord.module(), logRecord.resource().type())) {
            return;
        }
        log(logRecord, null);
    }

    private void handleAuditLogging(LogRecord logRecord, AuditLogOutput savedOutput) {
        AuditLogOutput output = savedOutput;
        if (savedOutput == null) {
            LoggingSettingsDto loggingSettingsDto = SettingsCache.getSettings(SettingsSection.LOGGING);
            if (loggingSettingsDto != null) output = loggingSettingsDto.getAuditLogs().getOutput();
        }

        if (output == null || output == AuditLogOutput.NONE) {
            return;
        }

        // log to DB
        if (output == AuditLogOutput.ALL || output == AuditLogOutput.DATABASE) {
            AuditLog auditLog = AuditLog.fromLogRecord(logRecord);
            auditLogRepository.save(auditLog);
        }

        // log to output
        if (output == AuditLogOutput.ALL || output == AuditLogOutput.CONSOLE) {
            logger.logAudited(logRecord);
        }
    }

}
