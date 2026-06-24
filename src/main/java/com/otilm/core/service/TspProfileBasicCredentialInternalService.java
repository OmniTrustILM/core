package com.otilm.core.service;

import java.util.UUID;

public interface TspProfileBasicCredentialInternalService {

    /**
     * Evicts the TSP profile model cache and credential-verification cache.
     */
    void evictCachesForSecret(UUID secretUuid);

    /**
     * Deletes the vault secret backing every Basic credential of the given TSP profile and evicts the
     * corresponding credential-verification cache entries.
     * Runs without an ambient transaction so the vault HTTP calls never hold a database transaction open.
     */
    void deleteSecretsForProfile(UUID tspProfileUuid);
}
