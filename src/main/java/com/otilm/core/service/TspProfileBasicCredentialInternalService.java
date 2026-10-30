package com.otilm.core.service;

import java.util.UUID;

public interface TspProfileBasicCredentialInternalService {

    /** Evicts the cached model of the TSP profile which holds the Basic credential secret. */
    void evictProfileModelForSecret(UUID secretUuid);

    /** Deletes the vault secret backing every Basic credential of the given TSP profile. */
    void deleteSecretsForProfile(UUID tspProfileUuid);
}
