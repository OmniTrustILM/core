package com.otilm.core.dao.repository.workflows;

import com.otilm.api.model.core.auth.Resource;
import com.otilm.api.model.core.other.ResourceEvent;
import com.otilm.core.dao.entity.workflows.TriggerAssociation;
import com.otilm.core.dao.repository.SecurityFilterRepository;
import org.springframework.data.jpa.repository.EntityGraph;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.UUID;

@Repository
public interface TriggerAssociationRepository extends SecurityFilterRepository<TriggerAssociation, UUID> {

    List<TriggerAssociation> findByTriggerUuid(UUID triggerUuid);

    List<TriggerAssociation> findAllByResourceAndObjectUuidOrderByTriggerOrderAsc(Resource resource, UUID objectUuid);

    @EntityGraph(attributePaths = {"trigger", "trigger.rules", "trigger.rules.conditions", "trigger.rules.conditions.items", "trigger.actions", "trigger.actions.executions", "trigger.actions.executions.items"})
    List<TriggerAssociation> findAllByEventAndResourceAndObjectUuidOrderByTriggerOrderAsc(ResourceEvent resourceEvent, Resource resource, UUID objectUuid);

    void deleteByTriggerUuid(UUID triggerUuid);

    Long deleteByResourceAndObjectUuid(Resource resource, UUID objectUuid);

    void deleteByEventAndResourceAndObjectUuid(ResourceEvent event, Resource resource, UUID objectUuid);

}
