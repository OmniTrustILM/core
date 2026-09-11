package com.otilm.core.api.web;

import com.otilm.api.exception.AlreadyExistException;
import com.otilm.api.exception.AttributeException;
import com.otilm.api.exception.ConnectorException;
import com.otilm.api.exception.NotFoundException;
import com.otilm.api.exception.SchedulerException;
import com.otilm.api.interfaces.core.web.DiscoveryController;
import com.otilm.api.model.client.certificate.DiscoveryResponseDto;
import com.otilm.api.model.client.certificate.SearchRequestDto;
import com.otilm.api.model.client.discovery.DiscoveryCertificateResponseDto;
import com.otilm.api.model.client.discovery.DiscoveryDetailDto;
import com.otilm.api.model.client.discovery.DiscoveryDto;
import com.otilm.api.model.common.PaginationResponseDto;
import com.otilm.api.model.common.UuidDto;
import com.otilm.api.model.common.attribute.common.BaseAttribute;
import com.otilm.api.model.connector.discovery.v2.DiscoverySupportedResourceDto;
import com.otilm.api.model.core.auth.Resource;
import com.otilm.api.model.core.discovery.DiscoveryItemDto;
import com.otilm.api.model.core.discovery.DiscoveryMessageDto;
import com.otilm.api.model.core.logging.enums.Module;
import com.otilm.api.model.core.logging.enums.Operation;
import com.otilm.api.model.core.scheduler.ScheduleDiscoveryDto;
import com.otilm.api.model.core.scheduler.ScheduledJobDetailDto;
import com.otilm.api.model.core.search.SearchFieldDataByGroupDto;
import com.otilm.core.aop.AuditLogged;
import com.otilm.core.logging.LogResource;
import com.otilm.core.security.authz.SecuredUUID;
import com.otilm.core.security.authz.SecurityFilter;
import com.otilm.core.service.DiscoveryExternalService;
import com.otilm.core.service.SchedulerExternalService;
import com.otilm.core.tasks.DiscoveryCertificateTask;
import com.otilm.core.util.converter.ResourceCodeConverter;
import java.net.URI;
import java.util.List;
import java.util.UUID;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.WebDataBinder;
import org.springframework.web.bind.annotation.InitBinder;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.servlet.support.ServletUriComponentsBuilder;

@RestController
public class DiscoveryControllerImpl implements DiscoveryController {

    private final Logger logger = LoggerFactory.getLogger(DiscoveryControllerImpl.class);

    private DiscoveryExternalService discoveryService;

    private SchedulerExternalService schedulerService;

    @Autowired
    public void setSchedulerService(SchedulerExternalService schedulerService) {
        this.schedulerService = schedulerService;
    }

    @Autowired
    public void setDiscoveryService(DiscoveryExternalService discoveryService) {
        this.discoveryService = discoveryService;
    }

    // ResourceCodeConverter goes through Resource.findByCode, whose ValidationException answers an unknown
    // code with a clean 422 — the global ConversionService route would 400 with Spring's class-name message.
    @InitBinder
    public void initBinder(final WebDataBinder webdataBinder) {
        webdataBinder.registerCustomEditor(Resource.class, new ResourceCodeConverter());
    }

    @Override
    @AuditLogged(module = Module.DISCOVERY, resource = Resource.DISCOVERY, operation = Operation.LIST)
    public DiscoveryResponseDto listDiscoveries(final SearchRequestDto request) {
        return discoveryService.listDiscoveries(SecurityFilter.create(), request);
    }

    @Override
    @AuditLogged(module = Module.DISCOVERY, resource = Resource.DISCOVERY, operation = Operation.DETAIL)
    public DiscoveryDetailDto getDiscovery(@LogResource(uuid = true) String uuid) throws NotFoundException {
        return discoveryService.getDiscovery(SecuredUUID.fromString(uuid));
    }

    @Override
    @AuditLogged(module = Module.DISCOVERY, resource = Resource.DISCOVERY, affiliatedResource = Resource.CERTIFICATE,
            operation = Operation.LIST)
    public DiscoveryCertificateResponseDto getDiscoveryCertificates(@LogResource(uuid = true) String uuid,
            Boolean newlyDiscovered, int itemsPerPage, int pageNumber) throws NotFoundException {
        return discoveryService
                .getDiscoveryCertificates(SecuredUUID.fromString(uuid), newlyDiscovered, itemsPerPage, pageNumber);
    }

    @Override
    @AuditLogged(module = Module.DISCOVERY, resource = Resource.DISCOVERY, operation = Operation.LIST)
    public PaginationResponseDto<DiscoveryMessageDto> getDiscoveryRunMessages(@LogResource(uuid = true) String uuid,
            int itemsPerPage, int pageNumber) throws NotFoundException {
        return discoveryService.getDiscoveryRunMessages(SecuredUUID.fromString(uuid), itemsPerPage, pageNumber);
    }

    @Override
    @AuditLogged(module = Module.DISCOVERY, resource = Resource.DISCOVERY, operation = Operation.CREATE)
    public ResponseEntity<?> createDiscovery(@RequestBody DiscoveryDto request)
            throws ConnectorException, AlreadyExistException, AttributeException, NotFoundException {
        final DiscoveryDetailDto modal = discoveryService.createDiscovery(request, true);
        discoveryService.runDiscoveryAsync(UUID.fromString(modal.getUuid()));
        URI location = ServletUriComponentsBuilder
                .fromCurrentRequest()
                .path("/{uuid}")
                .buildAndExpand(modal.getUuid())
                .toUri();
        UuidDto dto = new UuidDto();
        dto.setUuid(modal.getUuid());
        return ResponseEntity.created(location).body(dto);
    }

    @Override
    @AuditLogged(module = Module.SCHEDULER, resource = Resource.SCHEDULED_JOB, affiliatedResource = Resource.DISCOVERY,
            operation = Operation.SCHEDULE)
    public ResponseEntity<?> scheduleDiscovery(final ScheduleDiscoveryDto scheduleDiscoveryDto)
            throws SchedulerException, ConnectorException, AlreadyExistException, AttributeException,
            NotFoundException {
        final DiscoveryDto discoveryDto = scheduleDiscoveryDto.getRequest();
        discoveryService.createDiscovery(discoveryDto, false);

        String jobName;
        if (scheduleDiscoveryDto.getJobName() == null) {
            jobName = discoveryDto.getName();
        } else {
            jobName = scheduleDiscoveryDto.getJobName();
        }

        ScheduledJobDetailDto scheduledJob = schedulerService
                .registerScheduledJob(DiscoveryCertificateTask.class, jobName, scheduleDiscoveryDto.getCronExpression(),
                        scheduleDiscoveryDto.isOneTime(), scheduleDiscoveryDto.getRequest());
        logger.info("Job {} was registered.", jobName);

        // TODO: construct location URI differently without hardcoded path
        URI location = ServletUriComponentsBuilder
                .fromCurrentContextPath()
                .path("/v1/scheduler/jobs/{uuid}")
                .buildAndExpand(scheduledJob.getUuid())
                .toUri();
        UuidDto dto = new UuidDto();
        dto.setUuid(scheduledJob.getUuid().toString());
        return ResponseEntity.created(location).body(dto);
    }

    @Override
    @AuditLogged(module = Module.DISCOVERY, resource = Resource.DISCOVERY, operation = Operation.DELETE)
    public void deleteDiscovery(@LogResource(uuid = true) @PathVariable String uuid) throws NotFoundException {
        discoveryService.deleteDiscovery(SecuredUUID.fromString(uuid));
    }

    @Override
    @AuditLogged(module = Module.DISCOVERY, resource = Resource.DISCOVERY, operation = Operation.DELETE)
    public void bulkDeleteDiscovery(@LogResource(uuid = true) List<String> discoveryUuids) throws NotFoundException {
        discoveryService.bulkRemoveDiscovery(SecuredUUID.fromList(discoveryUuids));
    }

    @Override
    @AuditLogged(module = Module.CORE, resource = Resource.SEARCH_FILTER, affiliatedResource = Resource.DISCOVERY,
            operation = Operation.LIST)
    public List<SearchFieldDataByGroupDto> getSearchableFieldInformation() {
        return discoveryService.getSearchableFieldInformationByGroup();
    }

    @Override
    @AuditLogged(module = Module.DISCOVERY, resource = Resource.CONNECTOR, affiliatedResource = Resource.DISCOVERY,
            operation = Operation.LIST_RESOURCES)
    public List<DiscoverySupportedResourceDto> listDiscoveryResources(@LogResource(uuid = true) String connectorUuid)
            throws NotFoundException, ConnectorException {
        return discoveryService.listDiscoveryResources(SecuredUUID.fromString(connectorUuid));
    }

    @Override
    @AuditLogged(module = Module.DISCOVERY, resource = Resource.ATTRIBUTE, name = "discovery",
            affiliatedResource = Resource.CONNECTOR, operation = Operation.LIST_ATTRIBUTES)
    public List<BaseAttribute> getDiscoveryAttributes(@LogResource(uuid = true, affiliated = true) String connectorUuid)
            throws NotFoundException, ConnectorException {
        return discoveryService.getDiscoveryAttributes(SecuredUUID.fromString(connectorUuid));
    }

    @Override
    @AuditLogged(module = Module.DISCOVERY, resource = Resource.ATTRIBUTE, name = "discovery",
            affiliatedResource = Resource.CONNECTOR, operation = Operation.LIST_ATTRIBUTES)
    public List<BaseAttribute> getDiscoveryResourceAttributes(
            @LogResource(uuid = true, affiliated = true) String connectorUuid,
            @LogResource(name = true) Resource resource) throws NotFoundException, ConnectorException {
        return discoveryService.getDiscoveryResourceAttributes(SecuredUUID.fromString(connectorUuid), resource);
    }

    @Override
    @AuditLogged(module = Module.DISCOVERY, resource = Resource.DISCOVERY, operation = Operation.LIST)
    public PaginationResponseDto<DiscoveryItemDto> getDiscoveryItems(@LogResource(uuid = true) String uuid,
            @LogResource(resource = true, affiliated = true) Resource resource, Boolean newlyDiscovered,
            int itemsPerPage, int pageNumber) throws NotFoundException {
        return discoveryService
                .getDiscoveryItems(SecuredUUID.fromString(uuid), resource, newlyDiscovered, itemsPerPage, pageNumber);
    }

    @Override
    @AuditLogged(module = Module.DISCOVERY, resource = Resource.DISCOVERY, operation = Operation.STOP)
    public void stopDiscovery(@LogResource(uuid = true) String uuid) throws NotFoundException, ConnectorException {
        discoveryService.stopDiscovery(SecuredUUID.fromString(uuid));
    }

    @Override
    @AuditLogged(module = Module.DISCOVERY, resource = Resource.DISCOVERY, operation = Operation.RESUME)
    public void resumeDiscovery(@LogResource(uuid = true) String uuid) throws NotFoundException, ConnectorException {
        discoveryService.resumeDiscovery(SecuredUUID.fromString(uuid));
    }

    @Override
    @AuditLogged(module = Module.DISCOVERY, resource = Resource.DISCOVERY, operation = Operation.CANCEL)
    public void cancelDiscovery(@LogResource(uuid = true) String uuid) throws NotFoundException, ConnectorException {
        discoveryService.cancelDiscovery(SecuredUUID.fromString(uuid));
    }

}
