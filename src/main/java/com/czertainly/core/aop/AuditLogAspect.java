package com.czertainly.core.aop;

import com.czertainly.api.model.common.Named;
import com.czertainly.api.model.common.enums.IPlatformEnum;
import com.czertainly.api.model.core.auth.Resource;
import com.czertainly.api.model.core.logging.Loggable;
import com.czertainly.api.model.core.logging.Sensitive;
import com.czertainly.api.model.core.logging.enums.AuditLogOutput;
import com.czertainly.api.model.core.logging.enums.Operation;
import com.czertainly.api.model.core.logging.enums.OperationResult;
import com.czertainly.api.model.core.logging.records.LogRecord;
import com.czertainly.api.model.core.logging.records.ResourceObjectIdentity;
import com.czertainly.api.model.core.logging.records.ResourceRecord;
import com.czertainly.api.model.core.settings.SettingsSection;
import com.czertainly.api.model.core.settings.logging.LoggingSettingsDto;
import com.czertainly.core.logging.AuditLogEnhancer;
import com.czertainly.core.logging.LogResource;
import com.czertainly.core.logging.LoggingHelper;
import com.czertainly.core.messaging.jms.producers.AuditLogsProducer;
import com.czertainly.core.messaging.model.AuditLogMessage;
import com.czertainly.core.settings.SettingsCache;
import com.czertainly.core.util.AuthHelper;
import com.czertainly.core.util.BeautificationUtil;
import lombok.extern.slf4j.Slf4j;
import org.aspectj.lang.ProceedingJoinPoint;
import org.aspectj.lang.annotation.Around;
import org.aspectj.lang.annotation.Aspect;
import org.aspectj.lang.reflect.MethodSignature;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.stereotype.Component;

import java.io.Serializable;
import java.lang.reflect.Parameter;
import java.time.OffsetDateTime;
import java.util.*;

@Slf4j
@Aspect
@Component
public class AuditLogAspect {

    @Value("${logging.schema-version}")
    private String schemaVersion;

    private AuditLogsProducer auditLogsProducer;

    private AuditLogEnhancer auditLogEnhancer;

    @Autowired
    public void setAuditLogEnhancer(AuditLogEnhancer auditLogEnhancer) {
        this.auditLogEnhancer = auditLogEnhancer;
    }

    @Autowired
    public void setAuditLogsProducer(AuditLogsProducer auditLogsProducer) {
        this.auditLogsProducer = auditLogsProducer;
    }


    @Around("@annotation(AuditLogged)")
    public Object log(ProceedingJoinPoint joinPoint) throws Throwable {
        LoggingSettingsDto loggingSettingsDto = SettingsCache.getSettings(SettingsSection.LOGGING);
        if (loggingSettingsDto == null || (loggingSettingsDto.getAuditLogs().getOutput() == AuditLogOutput.NONE)) {
            return joinPoint.proceed();
        }

        AuditLogOutput output = loggingSettingsDto.getAuditLogs().getOutput();

        MethodSignature signature = (MethodSignature) joinPoint.getSignature();
        AuditLogged annotation = signature.getMethod().getAnnotation(AuditLogged.class);

        LogRecord.LogRecordBuilder logBuilder = LogRecord.builder()
                .version(schemaVersion) // hardcoded for now
                .audited(true)
                .module(annotation.module())
                .actor(LoggingHelper.getActorInfo())
                .source(LoggingHelper.getSourceInfo());

        Object result = null;

        LogData logData = constructLogData(annotation, logBuilder, signature.getMethod().getParameters(), joinPoint.getArgs(), loggingSettingsDto.getAuditLogs().isVerbose());
        Resource resource = logData.resource();

        if (LoggingHelper.isLogFilteredBasedOnModuleAndResource(true, annotation.module(), resource)) {
            return joinPoint.proceed();
        }

        List<ResourceObjectIdentity> deletedObjectsIdentities = new ArrayList<>();
        List<ResourceObjectIdentity> deletedAffiliatedObjectsIdentities = new ArrayList<>();

        boolean isDeleteOperation = logData.operation() == Operation.DELETE || logData.operation() == Operation.FORCE_DELETE;
        if (isDeleteOperation) {
            if (logData.resourceUuids() != null) {
                deletedObjectsIdentities = auditLogEnhancer.enrichObjectUuids(logData.resourceUuids(), resource);
            }
            if (logData.affiliatedResource() != Resource.NONE && logData.affiliatedResourceUuids() != null) {
                deletedAffiliatedObjectsIdentities = auditLogEnhancer.enrichObjectUuids(logData.affiliatedResourceUuids(), logData.affiliatedResource());
            }
        }

        try {
            result = joinPoint.proceed();
            logBuilder.operationResult(OperationResult.SUCCESS);
            return result;
        } catch (Exception e) {
            String message = e.getMessage();
            if (e instanceof AccessDeniedException) {
                String resourceNameAccessDenied = AuthHelper.getDeniedPermissionResource();
                String resourceActionName = AuthHelper.getDeniedPermissionResourceAction();
                message = "%s. Required '%s' action permission for resource '%s'".formatted(message, BeautificationUtil.camelToHumanForm(resourceActionName), Resource.findByCode(resourceNameAccessDenied).getLabel());
            }

            logBuilder.operationResult(OperationResult.FAILURE);
            logBuilder.message(message);
            throw e;
        } finally {
            addDataFromResponse(logBuilder, result);
            setResourceRecords(logData, isDeleteOperation, deletedObjectsIdentities, annotation, logBuilder, deletedAffiliatedObjectsIdentities);
            logBuilder.timestamp(OffsetDateTime.now());
            auditLogsProducer.produceMessage(new AuditLogMessage(logBuilder.build(), output));
        }
    }

    private void setResourceRecords(LogData logData, boolean isDeleteOperation, List<ResourceObjectIdentity> deletedObjectsIdentities, AuditLogged annotation, LogRecord.LogRecordBuilder logBuilder, List<ResourceObjectIdentity> deletedAffiliatedObjectsIdentities) {
        ResourceRecord resourceRecord;
        if (isDeleteOperation)
            resourceRecord = new ResourceRecord(logData.resource(), deletedObjectsIdentities);
        else
            resourceRecord = constructResourceRecord(false, logData.resource(), logData.resourceUuids(), annotation.name().isEmpty() ? logData.resourceName() : annotation.name());
        logBuilder.resource(resourceRecord);
        if (logData.affiliatedResource() != Resource.NONE) {
            ResourceRecord affiliatedResourceRecord;
            if (isDeleteOperation)
                affiliatedResourceRecord = new ResourceRecord(logData.affiliatedResource(), deletedAffiliatedObjectsIdentities);
            else
                affiliatedResourceRecord = constructResourceRecord(true, logData.affiliatedResource(), logData.affiliatedResourceUuids(), logData.affiliatedResourceName());
            logBuilder.affiliatedResource(affiliatedResourceRecord);
        }
    }

    private LogData constructLogData(AuditLogged annotation, LogRecord.LogRecordBuilder logBuilder, Parameter[] parameters, Object[] parameterValues, boolean verbose) {

        Map<String, Object> data = new LinkedHashMap<>();
        Resource resource = null;
        String resourceName = null;
        List<UUID> resourceUuids = null;
        Resource affiliatedResource = null;
        String affiliatedResourceName = null;
        List<UUID> affiliatedResourceUuids = null;

        if (parameters != null && parameterValues != null) {
            for (int i = 0; i < parameters.length; i++) {
                String parameterName = parameters[i].getName();
                Object parameterValue = parameterValues[i];

                LogResource logResource = parameters[i].getAnnotation(LogResource.class);
                List<UUID> paramResourceUuids = getResourceUuidsFromParameter(logResource, parameterName, parameterValue);
                String paramResourceName = getResourceNameFromParameter(logResource, parameterValue);
                Resource paramResource = getResourceFromParameter(logResource, parameterValue);

                boolean isAffiliated = logResource != null && logResource.affiliated();
                if (isAffiliated) {
                    if (paramResourceUuids != null) affiliatedResourceUuids = paramResourceUuids;
                    if (paramResourceName != null) affiliatedResourceName = paramResourceName;
                    if (paramResource != null) affiliatedResource = paramResource;
                } else {
                    if (paramResourceUuids != null) resourceUuids = paramResourceUuids;
                    if (paramResourceName != null) resourceName = paramResourceName;
                    if (paramResource != null) resource = paramResource;
                }

                if ((paramResourceUuids == null || paramResourceName == null) && parameterValues[i] instanceof Loggable loggable) {
                    if (paramResourceUuids == null && !loggable.toLogResourceObjectsUuids().isEmpty())
                        resourceUuids = loggable.toLogResourceObjectsUuids();
                    if (paramResourceName == null && !loggable.toLogResourceObjectsNames().isEmpty())
                        resourceName = loggable.toLogResourceObjectsNames().getFirst();
                }

                if (verbose && !parameters[i].isAnnotationPresent(Sensitive.class)) {
                    if (parameterValue instanceof Optional<?> optional) {
                        parameterValue = optional.orElse(null);
                    }
                    data.put(parameterName, parameterValue);
                }
            }
        }

        if (resource == null) resource = annotation.resource();
        if (affiliatedResource == null) affiliatedResource = annotation.affiliatedResource();

        Operation operation = annotation.operation() != Operation.UNKNOWN ? annotation.operation() : LoggingHelper.getAuditLogOperation();
        logBuilder.operation(operation);
        if (!data.isEmpty()) {
            logBuilder.additionalData(data);
        }

        return new LogData(resource, resourceName, resourceUuids, affiliatedResource, affiliatedResourceName, affiliatedResourceUuids, operation);
    }

    private Resource getResourceFromParameter(LogResource logResource, Object parameterValue) {
        return logResource != null && logResource.resource() && parameterValue instanceof Resource resourceInstance ? resourceInstance : null;
    }

    private List<UUID> getResourceUuidsFromParameter(LogResource logResource, String parameterName, Object parameterValue) {
        if (parameterValue == null) return null;
        if (logResource != null) {
            if (logResource.uuid()) {
                if (parameterValue instanceof Optional<?> optional) {
                    if (optional.isEmpty()) return null;
                    parameterValue = optional.get();
                }

                return parameterValue instanceof List<?> listValues
                        ? listValues.stream().map(v -> UUID.fromString(v.toString())).toList()
                        : (parameterValue instanceof Optional<?> optional && optional.isPresent() ? new ArrayList<>(List.of(UUID.fromString(optional.get().toString()))) : new ArrayList<>(List.of(UUID.fromString(parameterValue.toString()))));
            }
            return null;
        }
        if (parameterName.equalsIgnoreCase("uuid")) {
            if (parameterValue instanceof String paramString) {
                return new ArrayList<>(List.of(UUID.fromString(paramString)));
            }
            if (parameterValue instanceof UUID paramUuid) {
                return new ArrayList<>(List.of(paramUuid));
            }
        }

        return null;
    }

    private String getResourceNameFromParameter(LogResource logResource, Object parameterValue) {
        if (logResource != null) {
            if (logResource.name()) {
                return parameterValue instanceof IPlatformEnum platformEnum ? platformEnum.getCode() : parameterValue.toString();
            }
            return null;
        }
        if (parameterValue instanceof Named named) {
            return named.getName();
        }
        return null;
    }

    private ResourceRecord constructResourceRecord(boolean affiliated, Resource resource, List<UUID> resourceUuids, String resourceName) {
        List<ResourceObjectIdentity> objects = null;

        // If there are more UUIDs, for now it is assumed that names are not available (neither from MDC), and we will only add them without name
        if (resourceUuids != null && resourceUuids.size() > 1) {
            objects = new ArrayList<>(resourceUuids.stream().map(uuid -> new ResourceObjectIdentity(null, uuid)).toList());
        } else if (resourceUuids == null || resourceUuids.size() == 1) { // For empty list, objects are null
            // Otherwise there is only one resource object
            ResourceObjectIdentity objectIdentityFromMDC = getObjectIdentityFromMDC(resourceUuids, resourceName, affiliated, resource);
            if (objectIdentityFromMDC != null) objects = new ArrayList<>(List.of(objectIdentityFromMDC));
        }

        return new ResourceRecord(resource, objects);
    }

    private ResourceObjectIdentity getObjectIdentityFromMDC(List<UUID> resourceUuids, String resourceName, boolean affiliated, Resource resource) {
        UUID loggedResourceUuid = resourceUuids == null ? null : resourceUuids.getFirst();
        String loggedResourceName = resourceName;
        // If one at least of these is missing, try to enhance it from MDC
        if (loggedResourceName == null || loggedResourceUuid == null) {
            ResourceRecord storedResource = LoggingHelper.getLogResourceInfo(affiliated);
            if (objectIdentityAvailable(resource, storedResource)) {
                ResourceObjectIdentity objectIdentity = storedResource.objects().getFirst();
                // If UUID is missing and the name is same, add the stored UUID (or if both are missing)
                if (loggedResourceUuid == null && (objectIdentity.name().equals(resourceName) || resourceName == null))
                    loggedResourceUuid = objectIdentity.uuid();
                // If name is missing and the UUID is same, add the stored name (or if both are missing)
                if (loggedResourceName == null && (objectIdentity.uuid().equals(loggedResourceUuid) || loggedResourceUuid == null))
                    loggedResourceName = objectIdentity.name();
            }

        }
        // If both stay null, return null
        return getResourceObjectIdentity(loggedResourceName, loggedResourceUuid);
    }

    private static ResourceObjectIdentity getResourceObjectIdentity(String loggedResourceName, UUID loggedResourceUuid) {
        return loggedResourceName == null && loggedResourceUuid == null ? null : new ResourceObjectIdentity(loggedResourceName, loggedResourceUuid);
    }

    private static boolean objectIdentityAvailable(Resource resource, ResourceRecord storedResource) {
        return storedResource != null && Objects.equals(storedResource.type(), resource) && storedResource.objects() != null && !storedResource.objects().isEmpty();
    }

    private void addDataFromResponse(LogRecord.LogRecordBuilder builder, Object response) {
        Serializable responseOperationData = null;
        if (response != null) {
            if (response instanceof ResponseEntity<?> responseEntity) {
                response = responseEntity.getBody();
            }

            if (response instanceof Loggable loggable) {
                responseOperationData = loggable.toLogData();
            }
        }
        builder.operationData(responseOperationData);
    }

    private record LogData(
            Resource resource,
            String resourceName,
            List<UUID> resourceUuids,
            Resource affiliatedResource,
            String affiliatedResourceName,
            List<UUID> affiliatedResourceUuids,
            Operation operation
    ) {
    }

}
