package com.czertainly.core.dao.repository.signing;

import com.czertainly.core.dao.entity.signing.TspProfile;
import com.czertainly.core.dao.repository.SecurityFilterRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;
import java.util.UUID;

@Repository
public interface TspProfileRepository extends SecurityFilterRepository<TspProfile, UUID> {
    Optional<TspProfile> findByName(String name);

    Optional<TspProfile> findWithAssociationsByName(String name);

    @Query("SELECT t.name FROM TspProfile t ORDER BY t.name")
    List<String> findAllNames();
}
