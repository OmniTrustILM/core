package com.otilm.core.dao.entity;

import com.otilm.api.model.core.audit.AuditLogDto;
import com.otilm.api.model.core.auth.Resource;
import com.otilm.api.model.core.logging.enums.*;
import com.otilm.api.model.core.logging.enums.Module;
import com.otilm.api.model.core.logging.records.LogRecord;
import com.otilm.core.logging.AuditLogExportDto;
import com.otilm.core.logging.LoggingHelper;
import com.otilm.core.util.DtoMapper;
import jakarta.persistence.*;
import lombok.Getter;
import lombok.RequiredArgsConstructor;
import lombok.Setter;
import lombok.ToString;
import org.hibernate.annotations.CreationTimestamp;
import org.hibernate.annotations.JdbcTypeCode;
import org.hibernate.proxy.HibernateProxy;
import org.hibernate.type.SqlTypes;

import java.io.Serializable;
import java.time.OffsetDateTime;
import java.util.Objects;
import java.util.UUID;

@Getter
@Setter
@ToString
@RequiredArgsConstructor
@Entity
@Table(name = "audit_log")
public class AuditLog implements Serializable, DtoMapper<AuditLogDto> {

    @Id
    @Column(name = "id", nullable = false)
    @GeneratedValue(strategy = GenerationType.SEQUENCE, generator = "audit_log_seq")
    @SequenceGenerator(name = "audit_log_seq", sequenceName = "audit_log_id_seq", allocationSize = 1)
    private Long id;

    @Column(name = "version", nullable = false)
    private String version;

    @CreationTimestamp
    @Column(name = "logged_at", nullable = false, updatable = false)
    protected OffsetDateTime loggedAt;

    @Column(name = "timestamp", nullable = false)
    protected OffsetDateTime timestamp;

    @Column(name = "module", nullable = false)
    @Enumerated(EnumType.STRING)
    private Module module;

    @Column(name = "actor_type", nullable = false)
    @Enumerated(EnumType.STRING)
    private ActorType actorType;

    @Column(name = "actor_auth_method", nullable = false)
    @Enumerated(EnumType.STRING)
    private AuthMethod actorAuthMethod;

    @Column(name = "actor_uuid")
    private UUID actorUuid;

    @Column(name = "actor_name")
    private String actorName;

    @Column(name = "resource", nullable = false)
    @Enumerated(EnumType.STRING)
    private Resource resource;

    @Column(name = "affiliated_resource")
    @Enumerated(EnumType.STRING)
    private Resource affiliatedResource;

    @Column(name = "operation", nullable = false)
    @Enumerated(EnumType.STRING)
    private Operation operation;

    @Column(name = "operation_result", nullable = false)
    @Enumerated(EnumType.STRING)
    private OperationResult operationResult;

    @Column(name = "message", columnDefinition = "text")
    private String message;

    @Column(name = "log_record", nullable = false, columnDefinition = "jsonb")
    @JdbcTypeCode(SqlTypes.JSON)
    private LogRecord logRecord;

    @Override
    public AuditLogDto mapToDto() {
        AuditLogDto dto = new AuditLogDto();
        dto.setId(id);
        dto.setVersion(version);
        dto.setLoggedAt(loggedAt);
        dto.setTimestamp(timestamp);
        dto.setModule(module);
        dto.setActor(logRecord.actor());
        dto.setSource(logRecord.source());
        dto.setResource(logRecord.resource());
        dto.setAffiliatedResource(logRecord.affiliatedResource());
        dto.setOperation(operation);
        dto.setOperationResult(operationResult);
        dto.setOperationData(logRecord.operationData());
        dto.setMessage(message);
        dto.setAdditionalData(logRecord.additionalData());
        return dto;
    }

    public AuditLogExportDto mapToExportDto() {
        AuditLogExportDto.AuditLogExportDtoBuilder builder = AuditLogExportDto.builder();
        builder.id(id);
        builder.version(version);
        builder.loggedAt(loggedAt);
        builder.module(module);
        builder.resource(resource);
        builder.timestamp(timestamp);
        builder.resourceObjects(LoggingHelper.formatResourceObjectForCsv(logRecord.resource().objects()));
        builder.affiliatedResource(affiliatedResource);
        if (logRecord.affiliatedResource() != null) {
            builder.affiliatedObjects(LoggingHelper.formatResourceObjectForCsv(logRecord.affiliatedResource().objects()));
        }
        builder.actorType(actorType);
        builder.actorAuthMethod(actorAuthMethod);
        builder.actorUuid(actorUuid);
        builder.actorName(actorName);
        if (logRecord.source() != null) {
            builder.ipAddress(logRecord.source().ipAddress());
            builder.userAgent(logRecord.source().userAgent());
        }
        builder.operation(operation);
        builder.operationResult(operationResult);
        builder.message(message);

        return builder.build();
    }

    public static AuditLog fromLogRecord(LogRecord logRecord) {
        AuditLog auditLog = new AuditLog();
        auditLog.setVersion(logRecord.version());
        auditLog.setModule(logRecord.module());
        auditLog.setActorType(logRecord.actor().type());
        auditLog.setActorAuthMethod(logRecord.actor().authMethod());
        auditLog.setActorUuid(logRecord.actor().uuid());
        auditLog.setActorName(logRecord.actor().name());
        auditLog.setResource(logRecord.resource().type());
        auditLog.setAffiliatedResource(logRecord.affiliatedResource() != null ? logRecord.affiliatedResource().type() : null);
        auditLog.setOperation(logRecord.operation());
        auditLog.setOperationResult(logRecord.operationResult());
        auditLog.setMessage(logRecord.message());
        auditLog.setLogRecord(logRecord);
        auditLog.setTimestamp(logRecord.timestamp());

        return auditLog;
    }

    @Override
    public final boolean equals(Object o) {
        if (this == o) return true;
        if (o == null) return false;
        Class<?> oEffectiveClass = o instanceof HibernateProxy p ? p.getHibernateLazyInitializer().getPersistentClass() : o.getClass();
        Class<?> thisEffectiveClass = this instanceof HibernateProxy p ? p.getHibernateLazyInitializer().getPersistentClass() : this.getClass();
        if (thisEffectiveClass != oEffectiveClass) return false;
        if (!(o instanceof AuditLog auditLog)) return false;
        return getId() != null && Objects.equals(getId(), auditLog.getId());
    }

    @Override
    public final int hashCode() {
        return this instanceof HibernateProxy p ? p.getHibernateLazyInitializer().getPersistentClass().hashCode() : getClass().hashCode();
    }
}
