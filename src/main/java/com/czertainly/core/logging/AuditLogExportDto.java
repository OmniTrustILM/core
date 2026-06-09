package com.czertainly.core.logging;

import com.otilm.api.model.core.auth.Resource;
import com.otilm.api.model.core.logging.enums.*;
import com.otilm.api.model.core.logging.enums.Module;
import com.fasterxml.jackson.annotation.JsonPropertyOrder;
import lombok.Builder;

import java.io.Serializable;
import java.time.OffsetDateTime;
import java.util.UUID;

@Builder
@JsonPropertyOrder({"id", "version", "loggedAt", "timestamp", "module", "operation", "operationResult",
        "resource", "resourceObjects",
        "affiliatedResource", "affiliatedObjects",
        "actorType", "actorAuthMethod", "actorUuid", "actorName",
        "ipAddress", "userAgent", "message", "operationData", "additionalData"})
public record AuditLogExportDto(
        long id,
        String version,
        OffsetDateTime loggedAt,
        OffsetDateTime timestamp,
        Module module,
        Resource resource,
        String resourceObjects,
        Resource affiliatedResource,
        String affiliatedObjects,
        ActorType actorType,
        AuthMethod actorAuthMethod,
        UUID actorUuid,
        String actorName,
        String ipAddress,
        String userAgent,
        Operation operation,
        OperationResult operationResult,
        String message,
        String operationData,
        String additionalData
) implements Serializable {
}
