package com.otilm.core.dao.repository;

import com.otilm.core.dao.entity.VaultProfile;
import org.springframework.data.jpa.repository.Query;

import java.util.List;
import java.util.UUID;

public interface VaultProfileRepository extends SecurityFilterRepository<VaultProfile, UUID> {

    boolean existsByName(String name);

    @Query("SELECT vp.name FROM VaultProfile vp")
    List<String> findAllNames();

    @Query("SELECT vp.name FROM VaultProfile vp WHERE vp.vaultInstance.uuid = ?1")
    List<String> findAllNamesByVaultInstanceUuid(UUID uuid);
}
