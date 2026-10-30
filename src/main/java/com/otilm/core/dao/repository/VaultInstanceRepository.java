package com.otilm.core.dao.repository;

import com.otilm.core.dao.entity.VaultInstance;
import java.util.List;
import java.util.UUID;
import org.springframework.data.jpa.repository.Query;
import org.springframework.stereotype.Repository;

@Repository
public interface VaultInstanceRepository extends SecurityFilterRepository<VaultInstance, UUID> {

    boolean existsByName(String name);

    @Query("SELECT DISTINCT name FROM VaultInstance")
    List<String> findAllNames();

    @Query("SELECT DISTINCT connector.name FROM VaultInstance")
    List<String> findAllConnectorNames();
}
