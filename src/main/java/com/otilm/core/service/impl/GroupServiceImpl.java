package com.otilm.core.service.impl;

import com.otilm.api.exception.AlreadyExistException;
import com.otilm.api.exception.AttributeException;
import com.otilm.api.exception.NotFoundException;
import com.otilm.api.exception.ValidationError;
import com.otilm.api.exception.ValidationException;
import com.otilm.api.model.client.certificate.SearchFilterRequestDto;
import com.otilm.api.model.common.NameAndUuidDto;
import com.otilm.api.model.core.auth.Resource;
import com.otilm.api.model.core.auth.UserWithPaginationDto;
import com.otilm.api.model.core.certificate.group.GroupDto;
import com.otilm.api.model.core.certificate.group.GroupRequestDto;
import com.otilm.api.model.core.scheduler.PaginationRequestDto;
import com.otilm.core.attribute.engine.AttributeEngine;
import com.otilm.core.dao.entity.Group;
import com.otilm.core.dao.entity.Group_;
import com.otilm.core.dao.repository.GroupRepository;
import com.otilm.core.model.auth.ResourceAction;
import com.otilm.core.security.authn.client.UserManagementApiClient;
import com.otilm.core.security.authz.ExternalAuthorization;
import com.otilm.core.security.authz.SecuredParentUUID;
import com.otilm.core.security.authz.SecuredUUID;
import com.otilm.core.security.authz.SecurityFilter;
import com.otilm.core.service.GroupExternalService;
import com.otilm.core.service.GroupInternalService;
import com.otilm.core.service.ResourceObjectAssociationService;
import jakarta.transaction.Transactional;
import jakarta.transaction.Transactional.TxType;
import java.util.List;
import java.util.UUID;
import java.util.stream.Collectors;
import org.apache.commons.lang3.StringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

@Service(Resource.Codes.GROUP)
@Transactional
public class GroupServiceImpl implements GroupExternalService, GroupInternalService {
    private static final Logger logger = LoggerFactory.getLogger(GroupServiceImpl.class);

    private GroupRepository groupRepository;

    private ResourceObjectAssociationService objectAssociationService;

    private AttributeEngine attributeEngine;

    private UserManagementApiClient userManagementApiClient;

    @Autowired
    public void setGroupRepository(GroupRepository groupRepository) {
        this.groupRepository = groupRepository;
    }

    @Autowired
    public void setObjectAssociationService(ResourceObjectAssociationService objectAssociationService) {
        this.objectAssociationService = objectAssociationService;
    }

    @Autowired
    public void setAttributeEngine(AttributeEngine attributeEngine) {
        this.attributeEngine = attributeEngine;
    }

    @Autowired
    public void setUserManagementApiClient(UserManagementApiClient userManagementApiClient) {
        this.userManagementApiClient = userManagementApiClient;
    }

    @Override
    @ExternalAuthorization(resource = Resource.GROUP, action = ResourceAction.LIST)
    public List<GroupDto> listGroups(SecurityFilter filter) {
        return groupRepository
                .findUsingSecurityFilter(filter)
                .stream()
                .map(Group::mapToDto)
                .collect(Collectors.toList());
    }

    @Override
    @ExternalAuthorization(resource = Resource.GROUP, action = ResourceAction.DETAIL)
    public GroupDto getGroup(SecuredUUID uuid) throws NotFoundException {
        GroupDto dto = getGroupEntity(uuid).mapToDto();
        dto.setCustomAttributes(attributeEngine.getObjectCustomAttributesContent(Resource.GROUP, uuid.getValue()));
        return dto;
    }

    @Override
    @ExternalAuthorization(resource = Resource.GROUP, action = ResourceAction.CREATE)
    public GroupDto createGroup(GroupRequestDto request)
            throws ValidationException, AlreadyExistException, NotFoundException, AttributeException {
        if (StringUtils.isBlank(request.getName())) {
            throw new ValidationException(ValidationError.create("Name must not be empty"));
        }

        if (groupRepository.findByName(request.getName()).isPresent()) {
            throw new AlreadyExistException(Group.class, request.getName());
        }
        attributeEngine.validateCustomAttributesContent(Resource.GROUP, request.getCustomAttributes());

        Group group = new Group();
        group.setName(request.getName());
        group.setDescription(request.getDescription());
        group.setEmail(request.getEmail());
        groupRepository.save(group);

        GroupDto dto = group.mapToDto();
        dto
                .setCustomAttributes(attributeEngine
                        .updateObjectCustomAttributesContent(Resource.GROUP, group.getUuid(),
                                request.getCustomAttributes()));
        return dto;
    }

    @Override
    @ExternalAuthorization(resource = Resource.GROUP, action = ResourceAction.UPDATE)
    public GroupDto editGroup(SecuredUUID uuid, GroupRequestDto request) throws NotFoundException, AttributeException {
        Group group = getGroupEntity(uuid);
        attributeEngine.validateCustomAttributesContent(Resource.GROUP, request.getCustomAttributes());

        group.setDescription(request.getDescription());
        group.setEmail(request.getEmail());
        groupRepository.save(group);

        GroupDto dto = group.mapToDto();
        dto
                .setCustomAttributes(attributeEngine
                        .updateObjectCustomAttributesContent(Resource.GROUP, group.getUuid(),
                                request.getCustomAttributes()));
        return dto;
    }

    @Override
    @ExternalAuthorization(resource = Resource.GROUP, action = ResourceAction.DELETE)
    public void deleteGroup(SecuredUUID uuid) throws NotFoundException {
        Group group = getGroupEntity(uuid);

        objectAssociationService.removeGroupAssociations(group.getUuid());
        attributeEngine.deleteObjectAttributeContent(Resource.GROUP, group.getUuid());
        groupRepository.delete(group);
    }

    @Override
    @Transactional(TxType.NOT_SUPPORTED)
    @ExternalAuthorization(resource = Resource.USER, action = ResourceAction.LIST, parentResource = Resource.GROUP,
            parentAction = ResourceAction.MEMBERS)
    public List<NameAndUuidDto> getGroupUsers(SecuredParentUUID uuid) throws NotFoundException {
        String groupUuid = getGroupEntity(uuid).getUuid().toString();
        UserWithPaginationDto users = userManagementApiClient.getUsers();
        if (users.getTotalCount() != null && users.getTotalCount() > users.getData().size()) {
            logger
                    .warn("Auth service returned {} of {} users; members of group {} beyond that page are not listed",
                            users.getData().size(), users.getTotalCount(), groupUuid);
        }
        return users
                .getData()
                .stream()
                .filter(user -> user.getGroups().stream().anyMatch(g -> g.getUuid().equals(groupUuid)))
                .map(user -> new NameAndUuidDto(user.getUuid(), user.getUsername()))
                .toList();
    }

    @Override
    @ExternalAuthorization(resource = Resource.GROUP, action = ResourceAction.DELETE)
    public void bulkDeleteGroup(List<SecuredUUID> entityUuids) {
        for (SecuredUUID uuid : entityUuids) {
            try {
                deleteGroup(uuid);
            } catch (NotFoundException e) {
                logger.warn("Unable to find the group with uuid {}. It may have been deleted", uuid);
            }
        }
    }

    @Override
    @ExternalAuthorization(resource = Resource.GROUP, action = ResourceAction.LIST)
    public Long statisticsGroupCount(SecurityFilter filter) {
        return groupRepository.countUsingSecurityFilter(filter, null);
    }

    @Override
    public NameAndUuidDto getResourceObjectInternal(UUID objectUuid) throws NotFoundException {
        return groupRepository.findResourceObject(objectUuid, Group_.name);
    }

    @Override
    @ExternalAuthorization(resource = Resource.GROUP, action = ResourceAction.DETAIL)
    public NameAndUuidDto getResourceObjectExternal(SecuredUUID objectUuid) throws NotFoundException {
        return groupRepository.findResourceObject(objectUuid.getValue(), Group_.name);
    }

    @Override
    @ExternalAuthorization(resource = Resource.GROUP, action = ResourceAction.LIST)
    public List<NameAndUuidDto> listResourceObjects(SecurityFilter filter, List<SearchFilterRequestDto> filters,
            PaginationRequestDto pagination) {
        return groupRepository.listResourceObjects(filter, Group_.name);
    }

    @Override
    @ExternalAuthorization(resource = Resource.GROUP, action = ResourceAction.UPDATE)
    public void evaluatePermissionChain(SecuredUUID uuid) throws NotFoundException {
        getGroupEntity(uuid);
        // Since there are is no parent to the Group, exclusive parent permission evaluation need not be done
    }

    private Group getGroupEntity(SecuredUUID uuid) throws NotFoundException {
        return groupRepository.findByUuid(uuid).orElseThrow(() -> new NotFoundException(Group.class, uuid));
    }
}
