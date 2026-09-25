package com.otilm.core.messaging.jms.listeners;

import com.otilm.core.logging.AuditLogEnhancer;
import com.otilm.core.messaging.model.AuditLogMessage;
import com.otilm.core.service.AuditLogInternalService;
import lombok.AllArgsConstructor;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Transactional;

@Component
@Transactional
@AllArgsConstructor
public class AuditLogsListener implements MessageProcessor<AuditLogMessage> {

    private final AuditLogInternalService auditLogService;
    private final AuditLogEnhancer auditLogEnhancer;

    @Override
    public void processMessage(final AuditLogMessage auditLogMessage) {
        auditLogService
                .log(auditLogEnhancer.withObjectIdentities(auditLogMessage.getLogRecord()),
                        auditLogMessage.getAuditLogOutput());
    }

}
