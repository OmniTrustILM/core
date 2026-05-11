package com.czertainly.core.dao.repository.signing;

import com.czertainly.core.dao.entity.signing.TimeQualityConfiguration;
import com.czertainly.core.dao.repository.SecurityFilterRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;
import java.util.UUID;

@Repository
public interface TimeQualityConfigurationRepository extends SecurityFilterRepository<TimeQualityConfiguration, UUID> {

    Optional<TimeQualityConfiguration> findByName(String name);

    @Query("SELECT t.name FROM TimeQualityConfiguration t ORDER BY t.name")
    List<String> findAllNames();

    @Query(value = "SELECT DISTINCT unnest(ntp_servers) FROM {h-schema}time_quality_configuration ORDER BY 1", nativeQuery = true)
    List<String> findAllNtpServers();
}
