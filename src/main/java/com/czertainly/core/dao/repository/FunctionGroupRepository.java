package com.czertainly.core.dao.repository;

import com.otilm.api.model.core.connector.FunctionGroupCode;
import com.czertainly.core.dao.entity.FunctionGroup;
import org.springframework.stereotype.Repository;

import java.util.Optional;
import java.util.UUID;

@Repository
public interface FunctionGroupRepository extends SecurityFilterRepository<FunctionGroup, Long> {

    Optional<FunctionGroup> findByUuid(UUID uuid);

    Optional<FunctionGroup> findByName(String name);

    Optional<FunctionGroup> findByCode(FunctionGroupCode code);
}
