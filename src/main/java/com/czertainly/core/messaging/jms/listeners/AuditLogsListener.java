package com.czertainly.core.messaging.jms.listeners;

import com.czertainly.api.model.core.logging.records.LogRecord;
import com.czertainly.api.model.core.logging.records.ResourceRecord;
import com.czertainly.core.logging.AuditLogEnhancer;
import com.czertainly.core.messaging.model.AuditLogMessage;
import com.czertainly.core.service.AuditLogService;
import lombok.AllArgsConstructor;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Transactional;

@Component
@Transactional
@AllArgsConstructor
public class AuditLogsListener implements MessageProcessor<AuditLogMessage> {

    private final AuditLogService auditLogService;
    private final AuditLogEnhancer auditLogEnhancer;

    @Override
    public void processMessage(final AuditLogMessage auditLogMessage) {
        LogRecord logRecord = auditLogMessage.getLogRecord();
        LogRecord.LogRecordBuilder builder = LogRecord.builder()
                .audited(true)
                .timestamp(logRecord.timestamp())
                .version(logRecord.version())
                .message(logRecord.message())
                .actor(logRecord.actor())
                .additionalData(logRecord.additionalData())
                .module(logRecord.module())
                .source(logRecord.source())
                .operationData(logRecord.operationData())
                .operation(logRecord.operation())
                .operationResult(logRecord.operationResult())
                .resource(new ResourceRecord(logRecord.resource().type(), auditLogEnhancer.enrichObjectIdentities(logRecord.resource().objects(), logRecord.resource().type())))
                .affiliatedResource(logRecord.affiliatedResource() == null ? null : new ResourceRecord(logRecord.affiliatedResource().type(), auditLogEnhancer.enrichObjectIdentities(logRecord.affiliatedResource().objects(), logRecord.affiliatedResource().type())));
        auditLogService.log(builder.build(), auditLogMessage.getAuditLogOutput());
    }

}

