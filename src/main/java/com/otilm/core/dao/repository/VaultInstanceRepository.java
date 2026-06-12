package com.otilm.core.dao.repository;

import com.otilm.core.dao.entity.VaultInstance;
import org.springframework.data.jpa.repository.Query;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.UUID;

@Repository
public interface VaultInstanceRepository extends SecurityFilterRepository<VaultInstance, UUID> {

    boolean existsByName(String name);

    @Query("SELECT DISTINCT name FROM VaultInstance")
    List<String> findAllNames();

    @Query("SELECT DISTINCT connector.name FROM VaultInstance")
    List<String> findAllConnectorNames();
}
