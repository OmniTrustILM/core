package com.otilm.core.dao.repository.acme;

import com.otilm.core.dao.entity.acme.AcmeChallenge;
import com.otilm.core.dao.repository.SecurityFilterRepository;
import org.springframework.data.jpa.repository.EntityGraph;
import org.springframework.stereotype.Repository;

import java.util.Optional;
import java.util.UUID;

@Repository
public interface AcmeChallengeRepository extends SecurityFilterRepository<AcmeChallenge, Long> {

    Optional<AcmeChallenge> findByUuid(UUID uuid);

    @EntityGraph(attributePaths = {"authorization"})
    Optional<AcmeChallenge> findByChallengeId(String challengeId);
}
