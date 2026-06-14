package com.otilm.core.dao.repository;

import com.otilm.core.dao.entity.Secret;
import org.springframework.data.jpa.repository.EntityGraph;
import org.springframework.data.jpa.repository.Query;

import java.util.List;
import java.util.Optional;
import java.util.UUID;

public interface SecretRepository extends SecurityFilterRepository<Secret, UUID> {

    boolean existsByName(String name);

    Optional<Secret> findByUuid(UUID uuid);

    @Query("SELECT s.name FROM Secret s WHERE s.sourceVaultProfileUuid = :sourceVaultProfileUuid")
    List<String> findAllNamesBySourceVaultProfileUuid(UUID sourceVaultProfileUuid);

    @Query("SELECT s.name FROM Secret s JOIN s.syncVaultProfiles svp JOIN svp.vaultProfile vp WHERE vp.uuid = :syncVaultProfileUuid")
    List<String> findAllNamesBySyncVaultProfileUuid(UUID syncVaultProfileUuid);

    @EntityGraph(attributePaths = {"groups", "owner", "sourceVaultProfile", "latestVersion", "syncVaultProfiles"})
    Optional<Secret> findWithAssociationsByUuid(UUID uuid);

    List<Secret> findByUuidIn(List<UUID> objectUuids);

    @EntityGraph(attributePaths = {"latestVersion"})
    List<Secret> findWithLatestVersionByUuidIn(List<UUID> objectUuids);

    List<Secret> findBySourceVaultProfileUuid(UUID associationObjectUuid);
}
