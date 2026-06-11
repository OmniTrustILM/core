package com.otilm.core.dao.repository.workflows;

import com.otilm.core.dao.entity.workflows.Execution;
import com.otilm.core.dao.entity.workflows.ExecutionItem;
import com.otilm.core.dao.repository.SecurityFilterRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.util.UUID;

@Repository
public interface ExecutionItemRepository extends SecurityFilterRepository<ExecutionItem, UUID> {

    @Modifying
    @Query("DELETE FROM ExecutionItem ei WHERE ei.execution = :execution")
    void deleteByExecution(@Param("execution") Execution execution);

}
