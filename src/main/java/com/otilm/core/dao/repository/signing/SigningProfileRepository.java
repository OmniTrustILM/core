package com.otilm.core.dao.repository.signing;

import com.otilm.core.dao.entity.signing.SigningProfile;
import com.otilm.core.dao.repository.SecurityFilterRepository;
import com.otilm.core.model.signing.SigningProfileGateRow;
import java.util.List;
import java.util.Optional;
import java.util.UUID;
import org.springframework.data.jpa.repository.EntityGraph;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

@Repository
public interface SigningProfileRepository extends SecurityFilterRepository<SigningProfile, UUID> {
    List<SigningProfile> findAllByTspProfileUuid(UUID tspProfileUuid);

    List<SigningProfile> findAllByTimeQualityConfigurationUuid(UUID timeQualityConfigurationUuid);

    Optional<SigningProfile> findByName(String name);

    @EntityGraph(attributePaths = {"timeQualityConfiguration"})
    Optional<SigningProfile> findWithTimeQualityConfigurationByName(String name);

    @Query("SELECT s.name FROM SigningProfile s ORDER BY s.name")
    List<String> findAllNames();

    /**
     * Reads the profile's gate columns as scalars. An entity read here would stay managed for the rest of an
     * open-in-view request, and a later {@link #findByName} in that request would return it as it was read, missing an
     * update that committed in between.
     */
    @Query("""
            SELECT new com.otilm.core.model.signing.SigningProfileGateRow(
                s.name, s.ilmNativeEnabled, s.enabled, s.workflowType, s.signingScheme)
            FROM SigningProfile s
            WHERE s.uuid = :uuid
            """)
    Optional<SigningProfileGateRow> findGateRowByUuid(@Param("uuid") UUID uuid);
}
