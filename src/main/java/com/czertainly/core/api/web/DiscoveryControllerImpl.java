package com.czertainly.core.api.web;

import com.otilm.api.exception.*;
import com.otilm.api.interfaces.core.web.DiscoveryController;
import com.otilm.api.model.client.certificate.DiscoveryResponseDto;
import com.otilm.api.model.client.certificate.SearchRequestDto;
import com.otilm.api.model.client.discovery.DiscoveryCertificateResponseDto;
import com.otilm.api.model.client.discovery.DiscoveryDto;
import com.otilm.api.model.client.discovery.DiscoveryHistoryDetailDto;
import com.otilm.api.model.common.UuidDto;
import com.otilm.api.model.core.auth.Resource;
import com.otilm.api.model.core.logging.enums.Module;
import com.otilm.api.model.core.logging.enums.Operation;
import com.otilm.api.model.core.scheduler.ScheduleDiscoveryDto;
import com.otilm.api.model.core.scheduler.ScheduledJobDetailDto;
import com.otilm.api.model.core.search.SearchFieldDataByGroupDto;
import com.czertainly.core.aop.AuditLogged;
import com.czertainly.core.logging.LogResource;
import com.czertainly.core.security.authz.SecuredUUID;
import com.czertainly.core.security.authz.SecurityFilter;
import com.czertainly.core.service.DiscoveryService;
import com.czertainly.core.service.SchedulerExternalService;
import com.czertainly.core.tasks.DiscoveryCertificateTask;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.servlet.support.ServletUriComponentsBuilder;

import java.net.URI;
import java.util.List;
import java.util.UUID;

@RestController
public class DiscoveryControllerImpl implements DiscoveryController {

    private final Logger logger = LoggerFactory.getLogger(DiscoveryControllerImpl.class);

    private DiscoveryService discoveryService;

    private SchedulerExternalService schedulerService;

    @Autowired
    public void setSchedulerService(SchedulerExternalService schedulerService) {
        this.schedulerService = schedulerService;
    }

    @Autowired
    public void setDiscoveryService(DiscoveryService discoveryService) {
        this.discoveryService = discoveryService;
    }

    @Override
    @AuditLogged(module = Module.DISCOVERY, resource = Resource.DISCOVERY, operation = Operation.LIST)
    public DiscoveryResponseDto listDiscoveries(final SearchRequestDto request) {
        return discoveryService.listDiscoveries(SecurityFilter.create(), request);
    }

    @Override
    @AuditLogged(module = Module.DISCOVERY, resource = Resource.DISCOVERY, operation = Operation.DETAIL)
    public DiscoveryHistoryDetailDto getDiscovery(@LogResource(uuid = true) @PathVariable String uuid) throws NotFoundException {
        return discoveryService.getDiscovery(SecuredUUID.fromString(uuid));
    }

    @Override
    @AuditLogged(module = Module.DISCOVERY, resource = Resource.DISCOVERY, affiliatedResource = Resource.CERTIFICATE, operation = Operation.LIST)
    public DiscoveryCertificateResponseDto getDiscoveryCertificates(
            @LogResource(uuid = true) String uuid,
            Boolean newlyDiscovered,
            int itemsPerPage,
            int pageNumber
    ) throws NotFoundException {
        return discoveryService.getDiscoveryCertificates(
                SecuredUUID.fromString(uuid),
                newlyDiscovered,
                itemsPerPage,
                pageNumber
        );
    }

    @Override
    @AuditLogged(module = Module.DISCOVERY, resource = Resource.DISCOVERY, operation = Operation.CREATE)
    public ResponseEntity<?> createDiscovery(@RequestBody DiscoveryDto request) throws ConnectorException, AlreadyExistException, AttributeException, NotFoundException {
        final DiscoveryHistoryDetailDto modal = discoveryService.createDiscovery(request, true);
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
    @AuditLogged(module = Module.SCHEDULER, resource = Resource.SCHEDULED_JOB, affiliatedResource = Resource.DISCOVERY, operation = Operation.SCHEDULE)
    public ResponseEntity<?> scheduleDiscovery(final ScheduleDiscoveryDto scheduleDiscoveryDto) throws SchedulerException, ConnectorException, AlreadyExistException, AttributeException, NotFoundException {
        final DiscoveryDto discoveryDto = scheduleDiscoveryDto.getRequest();
        discoveryService.createDiscovery(discoveryDto, false);

        String jobName;
        if (scheduleDiscoveryDto.getJobName() == null) {
            jobName = discoveryDto.getName();
        } else {
            jobName = scheduleDiscoveryDto.getJobName();
        }

        ScheduledJobDetailDto scheduledJob = schedulerService.registerScheduledJob(DiscoveryCertificateTask.class, jobName, scheduleDiscoveryDto.getCronExpression(), scheduleDiscoveryDto.isOneTime(), scheduleDiscoveryDto.getRequest());
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
    @AuditLogged(module = Module.CORE, resource = Resource.SEARCH_FILTER, affiliatedResource = Resource.DISCOVERY, operation = Operation.LIST)
    public List<SearchFieldDataByGroupDto> getSearchableFieldInformation() {
        return discoveryService.getSearchableFieldInformationByGroup();
    }

}
