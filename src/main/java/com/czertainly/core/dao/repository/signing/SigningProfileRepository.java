package com.czertainly.core.dao.repository.signing;

import com.czertainly.core.dao.entity.signing.SigningProfile;
import com.czertainly.core.dao.repository.SecurityFilterRepository;
import org.springframework.data.jpa.repository.EntityGraph;
import org.springframework.data.jpa.repository.Query;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;
import java.util.UUID;

@Repository
public interface SigningProfileRepository extends SecurityFilterRepository<SigningProfile, UUID> {
    List<SigningProfile> findAllByTspProfileUuid(UUID tspProfileUuid);

    List<SigningProfile> findAllByTimeQualityConfigurationUuid(UUID timeQualityConfigurationUuid);

    Optional<SigningProfile> findByName(String name);

    @EntityGraph(attributePaths = {"timeQualityConfiguration"})
    Optional<SigningProfile> findWithTimeQualityConfigurationByName(String name);

    @Query("SELECT s.name FROM SigningProfile s ORDER BY s.name")
    List<String> findAllNames();
}
