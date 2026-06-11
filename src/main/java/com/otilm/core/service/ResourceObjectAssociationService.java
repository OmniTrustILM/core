package com.otilm.core.service;

import com.otilm.api.exception.NotFoundException;
import com.otilm.api.model.common.NameAndUuidDto;
import com.otilm.api.model.core.auth.Resource;
import com.otilm.api.model.core.notification.RecipientType;
import com.otilm.core.dao.entity.Group;

import java.util.List;
import java.util.Set;
import java.util.UUID;

public interface ResourceObjectAssociationService {
    List<UUID> getGroupUuids(Resource resource, UUID objectUuid);
    void addGroup(Resource resource, UUID objectUuid, UUID groupUuid) throws NotFoundException;
    Set<Group> setGroups(Resource resource, UUID objectUuid, Set<UUID> groupUuid) throws NotFoundException;
    void removeGroup(Resource resource, UUID objectUuid, UUID groupUuid);
    void removeGroupAssociations(UUID groupUuid);

    NameAndUuidDto getOwner(Resource resource, UUID objectUuid);
    NameAndUuidDto setOwner(Resource resource, UUID objectUuid, UUID ownerUuid) throws NotFoundException;
    void setOwnerFromProfile(Resource resource, UUID objectUuid);
    void removeOwnerAssociations(UUID ownerUuid);

    void removeObjectAssociations(Resource resource, UUID objectUuid);

    void bulkRemoveObjectAssociations(Resource resource, List<UUID> objectUuids);


    /**
     * Retrieves information (UUID and name) about object defined by its type and UUID
     * @param recipientType type of recipient
     * @param recipientUuid UUID of object defined by recipient
     * @return Name and UUID of object associated for such recipient type
     * @throws NotFoundException
     */
    NameAndUuidDto getRecipientObjectInfo(RecipientType recipientType, UUID recipientUuid) throws NotFoundException;
}
