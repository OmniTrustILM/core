package com.otilm.core.dao.repository.workflows;

import com.otilm.core.dao.entity.workflows.ConditionItem;
import com.otilm.core.dao.repository.SecurityFilterRepository;
import java.util.UUID;
import org.springframework.stereotype.Repository;

@Repository
public interface ConditionItemRepository extends SecurityFilterRepository<ConditionItem, UUID> {

}
