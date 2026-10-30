package com.otilm.core.dao.repository;

import com.otilm.api.model.core.connector.FunctionGroupCode;
import com.otilm.core.dao.entity.FunctionGroup;
import java.util.Optional;
import java.util.UUID;
import org.springframework.stereotype.Repository;

@Repository
public interface FunctionGroupRepository extends SecurityFilterRepository<FunctionGroup, Long> {

    Optional<FunctionGroup> findByUuid(UUID uuid);

    Optional<FunctionGroup> findByName(String name);

    Optional<FunctionGroup> findByCode(FunctionGroupCode code);
}
