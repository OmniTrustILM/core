package com.otilm.core.api.web;

import com.otilm.api.exception.AlreadyExistException;
import com.otilm.api.exception.AttributeException;
import com.otilm.api.exception.NotFoundException;
import com.otilm.api.exception.ValidationException;
import com.otilm.api.interfaces.core.web.GroupController;
import com.otilm.api.model.common.UuidDto;
import com.otilm.api.model.core.auth.Resource;
import com.otilm.api.model.core.certificate.group.GroupDto;
import com.otilm.api.model.core.certificate.group.GroupRequestDto;
import com.otilm.api.model.core.logging.enums.Module;
import com.otilm.api.model.core.logging.enums.Operation;
import com.otilm.core.aop.AuditLogged;
import com.otilm.core.auth.AuthEndpoint;
import com.otilm.core.logging.LogResource;
import com.otilm.core.security.authz.SecuredUUID;
import com.otilm.core.security.authz.SecurityFilter;
import com.otilm.core.service.GroupService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.servlet.support.ServletUriComponentsBuilder;

import java.net.URI;
import java.util.List;

@RestController
public class GroupControllerImpl implements GroupController {

    private GroupService groupService;

    @Autowired
    public void setGroupService(GroupService groupService) {
        this.groupService = groupService;
    }

    @Override
    @AuthEndpoint(resourceName = Resource.GROUP)
    @AuditLogged(module = Module.CORE, resource = Resource.GROUP, operation = Operation.LIST)
    public List<GroupDto> listGroups() {
        return groupService.listGroups(SecurityFilter.create());
    }

    @Override
    @AuditLogged(module = Module.CORE, resource = Resource.GROUP, operation = Operation.DETAIL)
    public GroupDto getGroup(@LogResource(uuid = true) @PathVariable String uuid) throws NotFoundException {
        return groupService.getGroup(SecuredUUID.fromString(uuid));
    }

    @Override
    @AuditLogged(module = Module.CORE, resource = Resource.GROUP, operation = Operation.CREATE)
    public ResponseEntity<?> createGroup(@RequestBody GroupRequestDto request) throws ValidationException, AlreadyExistException, NotFoundException, AttributeException {
        GroupDto groupDto = groupService.createGroup(request);

        URI location = ServletUriComponentsBuilder
                .fromCurrentRequest()
                .path("/{uuid}")
                .buildAndExpand(groupDto.getUuid())
                .toUri();
        UuidDto dto = new UuidDto();
        dto.setUuid(groupDto.getUuid());
        return ResponseEntity.created(location).body(dto);
    }

    @Override
    @AuditLogged(module = Module.CORE, resource = Resource.GROUP, operation = Operation.UPDATE)
    public GroupDto editGroup(@LogResource(uuid = true) @PathVariable String uuid, @RequestBody GroupRequestDto request) throws NotFoundException, AttributeException {
        return groupService.editGroup(SecuredUUID.fromString(uuid), request);
    }

    @Override
    @AuditLogged(module = Module.CORE, resource = Resource.GROUP, operation = Operation.DELETE)
    public void deleteGroup(@LogResource(uuid = true) @PathVariable String uuid) throws NotFoundException {
        groupService.deleteGroup(SecuredUUID.fromString(uuid));
    }

    @Override
    @AuditLogged(module = Module.CORE, resource = Resource.GROUP, operation = Operation.DELETE)
    public void bulkDeleteGroup(@LogResource(uuid = true) List<String> groupUuids) {
        groupService.bulkDeleteGroup(SecuredUUID.fromList(groupUuids));
    }
}
