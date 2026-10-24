package com.otilm.core.logging;

import com.fasterxml.jackson.annotation.JsonPropertyOrder;
import com.otilm.api.model.core.auth.Resource;
import com.otilm.api.model.core.logging.enums.ActorType;
import com.otilm.api.model.core.logging.enums.AuthMethod;
import com.otilm.api.model.core.logging.enums.Module;
import com.otilm.api.model.core.logging.enums.Operation;
import com.otilm.api.model.core.logging.enums.OperationResult;
import java.io.Serializable;
import java.time.OffsetDateTime;
import java.util.UUID;
import lombok.Builder;

@Builder
@JsonPropertyOrder({
        "id",
        "version",
        "loggedAt",
        "timestamp",
        "module",
        "operation",
        "operationResult",
        "resource",
        "resourceObjects",
        "affiliatedResource",
        "affiliatedObjects",
        "actorType",
        "actorAuthMethod",
        "actorUuid",
        "actorName",
        "ipAddress",
        "userAgent",
        "message",
        "operationData",
        "additionalData",
        "actorDelegateIdentifier",
        "actorDelegateSubject"})
public record AuditLogExportDto(long id, String version, OffsetDateTime loggedAt, OffsetDateTime timestamp,
        Module module, Resource resource, String resourceObjects, Resource affiliatedResource, String affiliatedObjects,
        ActorType actorType, AuthMethod actorAuthMethod, UUID actorUuid, String actorName, String ipAddress,
        String userAgent, Operation operation, OperationResult operationResult, String message, String operationData,
        String additionalData, String actorDelegateIdentifier, String actorDelegateSubject) implements Serializable {
}
