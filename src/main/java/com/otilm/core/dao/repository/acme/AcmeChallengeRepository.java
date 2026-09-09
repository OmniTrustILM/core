package com.otilm.core.dao.repository.acme;

import com.otilm.core.dao.entity.acme.AcmeChallenge;
import com.otilm.core.dao.repository.SecurityFilterRepository;
import java.util.Optional;
import java.util.UUID;
import org.springframework.data.jpa.repository.EntityGraph;
import org.springframework.stereotype.Repository;

@Repository
public interface AcmeChallengeRepository extends SecurityFilterRepository<AcmeChallenge, Long> {

    Optional<AcmeChallenge> findByUuid(UUID uuid);

    @EntityGraph(attributePaths = {"authorization"})
    Optional<AcmeChallenge> findByChallengeId(String challengeId);

    /**
     * Loads the challenge with its authorization, order, account and the account's profiles, which is everything the
     * challenge endpoint reads and returns. The endpoint runs without a transaction so that the DNS and HTTP lookups do
     * not hold one, and nothing may be loaded lazily once it has left the query.
     */
    @EntityGraph(attributePaths = {
            "authorization",
            "authorization.order",
            "authorization.order.authorizations",
            "authorization.order.authorizations.challenges",
            "authorization.order.acmeAccount",
            "authorization.order.acmeAccount.acmeProfile",
            "authorization.order.acmeAccount.raProfile"})
    Optional<AcmeChallenge> findWithContextByChallengeId(String challengeId);
}
