package com.otilm.core.dao.repository.acme;

import com.otilm.core.dao.entity.acme.AcmeAuthorization;
import com.otilm.core.dao.repository.SecurityFilterRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;
import java.util.UUID;

@Repository
public interface AcmeAuthorizationRepository extends SecurityFilterRepository<AcmeAuthorization, Long> {
    Optional<AcmeAuthorization> findByUuid(UUID uuid);
    Optional<AcmeAuthorization> findByAuthorizationId(String authorizationId);
}
