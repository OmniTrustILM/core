package com.czertainly.core.service;

import com.otilm.api.model.core.logging.enums.AuditLogOutput;
import com.otilm.api.model.core.logging.enums.Operation;
import com.otilm.api.model.core.logging.enums.OperationResult;
import com.otilm.api.model.core.logging.records.LogRecord;

public interface AuditLogInternalService {

    void log(LogRecord logRecord, AuditLogOutput logOutput);

    void logAuthentication(Operation operation, OperationResult operationResult, String message, String authData);
}
