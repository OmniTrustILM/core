package com.czertainly.core.service.impl;

import com.otilm.api.exception.NotFoundException;
import com.otilm.api.model.common.NameAndUuidDto;
import com.otilm.api.model.core.auth.Resource;
import com.otilm.api.model.core.auth.RoleDetailDto;
import com.otilm.api.model.core.auth.UserDetailDto;
import com.otilm.api.model.core.auth.UserProfileDto;
import com.otilm.api.model.core.notification.RecipientType;
import com.czertainly.core.dao.entity.Group;
import com.czertainly.core.dao.entity.GroupAssociation;
import com.czertainly.core.dao.entity.OwnerAssociation;
import com.czertainly.core.dao.repository.GroupAssociationRepository;
import com.czertainly.core.dao.repository.GroupRepository;
import com.czertainly.core.dao.repository.OwnerAssociationRepository;
import com.czertainly.core.security.authn.client.RoleManagementApiClient;
import com.czertainly.core.security.authn.client.UserManagementApiClient;
import com.czertainly.core.service.ResourceObjectAssociationService;
import com.czertainly.core.util.AuthHelper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.*;

@Service
@Transactional
public class ResourceObjectAssociationServiceImpl implements ResourceObjectAssociationService {
    private static final Logger logger = LoggerFactory.getLogger(ResourceObjectAssociationServiceImpl.class);

    private UserManagementApiClient userManagementApiClient;
    private RoleManagementApiClient roleManagementApiClient;

    private GroupRepository groupRepository;
    private GroupAssociationRepository groupAssociationRepository;
    private OwnerAssociationRepository ownerAssociationRepository;

    private final Map<UUID, String> mappedUsers = new HashMap<>();
    private final Map<UUID, String> mappedRoles = new HashMap<>();

    @Autowired
    public void setGroupAssociationRepository(GroupAssociationRepository groupAssociationRepository) {
        this.groupAssociationRepository = groupAssociationRepository;
    }

    @Autowired
    public void setOwnerAssociationRepository(OwnerAssociationRepository ownerAssociationRepository) {
        this.ownerAssociationRepository = ownerAssociationRepository;
    }

    @Autowired
    public void setGroupRepository(GroupRepository groupRepository) {
        this.groupRepository = groupRepository;
    }

    @Autowired
    public void setUserManagementApiClient(UserManagementApiClient userManagementApiClient) {
        this.userManagementApiClient = userManagementApiClient;
    }

    @Autowired
    public void setRoleManagementApiClient(RoleManagementApiClient roleManagementApiClient) {
        this.roleManagementApiClient = roleManagementApiClient;
    }

    @Override
    public void addGroup(Resource resource, UUID objectUuid, UUID groupUuid) throws NotFoundException {
        if (groupUuid != null && !groupAssociationRepository.existsByResourceAndObjectUuidAndGroupUuid(resource, objectUuid, groupUuid)) {
            createGroupAssociation(resource, objectUuid, groupUuid);
            logger.debug("Added group {} association to {} with UUID {}", groupUuid, resource.getLabel(), objectUuid);
        }
    }

    @Override
    public List<UUID> getGroupUuids(Resource resource, UUID objectUuid) {
        List<GroupAssociation> groupAssociations = groupAssociationRepository.findByResourceAndObjectUuid(resource, objectUuid);
        return groupAssociations.stream().map(GroupAssociation::getGroupUuid).toList();
    }

    @Override
    public Set<Group> setGroups(Resource resource, UUID objectUuid, Set<UUID> groupUuids) throws NotFoundException {
        Set<Group> groups = new HashSet<>();

        removeGroups(resource, objectUuid);
        if (groupUuids != null && !groupUuids.isEmpty()) {
            for (UUID groupUuid : groupUuids) {
                groups.add(createGroupAssociation(resource, objectUuid, groupUuid));
            }
            logger.debug("Added {} group associations to {} with UUID {}", groupUuids.size(), resource.getLabel(), objectUuid);
        }

        return groups;
    }

    @Override
    public void removeGroup(Resource resource, UUID objectUuid, UUID groupUuid) {
        if (groupUuid != null) {
            Long associationsDeleted = groupAssociationRepository.deleteByResourceAndObjectUuidAndGroupUuid(resource, objectUuid, groupUuid);
            if (associationsDeleted == 0) {
                logger.debug("Group {} not associated to {} with UUID {}", groupUuid, resource.getLabel(), objectUuid);
            } else {
                logger.debug("Removed group {} from {} with UUID {}", groupUuid, resource.getLabel(), objectUuid);
            }
        }
    }

    @Override
    public void removeGroupAssociations(UUID groupUuid) {
        if (groupUuid != null) {
            Long associationsDeleted = groupAssociationRepository.deleteByGroupUuid(groupUuid);
            logger.debug("Removed {} group associations of group UUID {}", associationsDeleted, groupUuid);
        }
    }

    @Override
    public NameAndUuidDto getOwner(Resource resource, UUID objectUuid) {
        OwnerAssociation ownerAssociation = ownerAssociationRepository.findByResourceAndObjectUuid(resource, objectUuid);
        return ownerAssociation == null ? null : new NameAndUuidDto(ownerAssociation.getOwnerUuid().toString(), ownerAssociation.getOwnerUsername());
    }

    @Override
    public NameAndUuidDto setOwner(Resource resource, UUID objectUuid, UUID ownerUuid) throws NotFoundException {
        String ownerUsername = null;
        OwnerAssociation ownerAssociation = ownerAssociationRepository.findByResourceAndObjectUuid(resource, objectUuid);
        if (ownerUuid == null) {
            if (ownerAssociation != null) {
                ownerAssociationRepository.delete(ownerAssociation);
                logger.debug("Removed owner from {} with UUID {}", resource.getLabel(), objectUuid);
            }
        } else {
            if (ownerAssociation == null || !ownerAssociation.getOwnerUuid().equals(ownerUuid)) {
                ownerUsername = getUserUsername(ownerUuid);

                if (ownerAssociation == null) {
                    createOwnerAssociation(resource, objectUuid, ownerUuid, ownerUsername);
                } else {
                    ownerAssociation.setOwnerUuid(ownerUuid);
                    ownerAssociation.setOwnerUsername(ownerUsername);
                    ownerAssociationRepository.save(ownerAssociation);
                }
                logger.debug("Added owner {} association to {} with UUID {}", ownerUsername, resource.getLabel(), objectUuid);
            }
        }

        return ownerUuid == null ? null : new NameAndUuidDto(ownerUuid.toString(), ownerUsername);
    }

    @Override
    public void setOwnerFromProfile(Resource resource, UUID objectUuid) {
        try {
            UserProfileDto userProfileDto = AuthHelper.getUserProfile();
            setOwner(resource, objectUuid, UUID.fromString(userProfileDto.getUser().getUuid()), userProfileDto.getUser().getUsername());
        } catch (Exception e) {
            logger.warn("Unable to set owner for {} {} to logged user: {}", resource.getLabel(), objectUuid, e.getMessage());
        }
    }

    @Override
    public void removeOwnerAssociations(UUID ownerUuid) {
        if (ownerUuid != null) {
            Long associationsDeleted = ownerAssociationRepository.deleteByOwnerUuid(ownerUuid);
            logger.debug("Removed {} owner associations of owner UUID {}", associationsDeleted, ownerUuid);
        }
    }

    @Override
    public void removeObjectAssociations(Resource resource, UUID objectUuid) {
        removeOwner(resource, objectUuid);
        removeGroups(resource, objectUuid);
    }

    @Override
    @Transactional
    public void bulkRemoveObjectAssociations(Resource resource, List<UUID> objectUuids) {
        removeOwner(resource, objectUuids);
        removeGroups(resource, objectUuids);
    }

    @Override
    public NameAndUuidDto getRecipientObjectInfo(RecipientType recipientType, UUID recipientUuid) throws NotFoundException {
        String name = switch (recipientType) {
            case USER -> getUserUsername(recipientUuid);
            case GROUP -> {
                Group group = groupRepository.findByUuid(recipientUuid).orElseThrow(() -> new NotFoundException(Group.class, recipientUuid));
                yield group.getName();
            }
            case ROLE -> getRoleName(recipientUuid);
            default -> null;
        };

        return name == null ? null : new NameAndUuidDto(recipientUuid.toString(), name);
    }

    private void removeGroups(Resource resource, UUID objectUuid) {
        Long associationsDeleted = groupAssociationRepository.deleteByResourceAndObjectUuid(resource, objectUuid);
        logger.debug("Removed {} groups from {} with UUID {}", associationsDeleted, resource.getLabel(), objectUuid);
    }

    private void removeGroups(Resource resource, List<UUID> objectUuids) {
        Long associationsDeleted = groupAssociationRepository.deleteByResourceAndObjectUuidIn(resource, objectUuids);
        logger.debug("Removed {} groups from {} with UUIDs {}", associationsDeleted, resource.getLabel(), objectUuids);
    }

    private void setOwner(Resource resource, UUID objectUuid, UUID ownerUuid, String ownerUsername) {
        OwnerAssociation ownerAssociation = ownerAssociationRepository.findByResourceAndObjectUuid(resource, objectUuid);
        if (ownerUuid == null) {
            if (ownerAssociation != null) {
                ownerAssociationRepository.delete(ownerAssociation);
                logger.debug("Removed owner from {} with UUID {}", resource.getLabel(), objectUuid);
            }
        } else {
            mappedUsers.put(ownerUuid, ownerUsername);
            if (ownerAssociation == null) {
                createOwnerAssociation(resource, objectUuid, ownerUuid, ownerUsername);
            } else {
                ownerAssociation.setOwnerUuid(ownerUuid);
                ownerAssociation.setOwnerUsername(ownerUsername);
                ownerAssociationRepository.save(ownerAssociation);
            }

            logger.debug("Added owner {} association to {} with UUID {}", ownerUsername, resource.getLabel(), objectUuid);
        }
    }

    private void removeOwner(Resource resource, UUID objectUuid) {
        Long associationsDeleted = ownerAssociationRepository.deleteByResourceAndObjectUuidAndOwnerUuidNotNull(resource, objectUuid);
        if (associationsDeleted == 0) {
            logger.debug("Owner not associated to {} with UUID {}", resource.getLabel(), objectUuid);
        } else {
            logger.debug("Removed owner from {} with UUID {}", resource.getLabel(), objectUuid);
        }
    }

    private void removeOwner(Resource resource, List<UUID> objectUuids) {
        Long associationsDeleted = ownerAssociationRepository.deleteByResourceAndObjectUuidInAndOwnerUuidNotNull(resource, objectUuids);
        if (associationsDeleted == 0) {
            logger.debug("Owner not associated to {} for any of the UUIDs {}", resource.getLabel(), objectUuids);
        } else {
            logger.debug("Removed owner from {} with UUIDs {}", resource.getLabel(), objectUuids);
        }
    }

    private Group createGroupAssociation(Resource resource, UUID objectUuid, UUID groupUuid) throws NotFoundException {
        Group group = groupRepository.findByUuid(groupUuid).orElseThrow(() -> new NotFoundException(Group.class, groupUuid));

        GroupAssociation association = new GroupAssociation();
        association.setResource(resource);
        association.setObjectUuid(objectUuid);
        association.setGroupUuid(groupUuid);
        groupAssociationRepository.save(association);

        return group;
    }

    private void createOwnerAssociation(Resource resource, UUID objectUuid, UUID ownerUuid, String username) {
        OwnerAssociation association = new OwnerAssociation();
        association.setResource(resource);
        association.setObjectUuid(objectUuid);
        association.setOwnerUuid(ownerUuid);
        association.setOwnerUsername(username);
        ownerAssociationRepository.save(association);
    }

    private String getUserUsername(UUID userUuid) throws NotFoundException {
        String username;
        if ((username = mappedUsers.get(userUuid)) == null) {
            try {
                UserDetailDto userDetail = userManagementApiClient.getUserDetail(userUuid.toString());
                username = userDetail.getUsername();
                mappedUsers.put(userUuid, username);
            } catch (Exception ex) {
                throw new NotFoundException("User", userUuid);
            }
        }

        return username;
    }

    private String getRoleName(UUID roleUuid) throws NotFoundException {
        String name;
        if ((name = mappedRoles.get(roleUuid)) == null) {
            try {
                RoleDetailDto roleDetail = roleManagementApiClient.getRoleDetail(roleUuid.toString());
                name = roleDetail.getName();
                mappedRoles.put(roleUuid, name);
            } catch (Exception ex) {
                throw new NotFoundException("Role", roleUuid);
            }
        }

        return name;
    }
}
