package com.czertainly.core.dao.repository.workflows;

import com.otilm.api.model.core.auth.Resource;
import com.czertainly.core.dao.entity.workflows.Trigger;
import com.czertainly.core.dao.repository.SecurityFilterRepository;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.UUID;

@Repository
public interface TriggerRepository extends SecurityFilterRepository<Trigger, UUID> {

    boolean existsByName(String name);

    boolean existsByNameAndUuidNot(String name, UUID uuid);

    List<Trigger> findAllByResource(Resource resource);

}
