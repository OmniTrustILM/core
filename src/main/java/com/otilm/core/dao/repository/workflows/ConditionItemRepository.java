package com.otilm.core.dao.repository.workflows;

import com.otilm.core.dao.entity.workflows.ConditionItem;
import com.otilm.core.dao.repository.SecurityFilterRepository;
import org.springframework.stereotype.Repository;

import java.util.UUID;

@Repository
public interface ConditionItemRepository extends SecurityFilterRepository<ConditionItem, UUID> {


}
