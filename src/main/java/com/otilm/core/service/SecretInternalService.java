package com.otilm.core.service;

import com.otilm.api.exception.*;
import com.otilm.api.model.client.dashboard.StatisticsDto;
import com.otilm.core.messaging.model.ActionMessage;
import com.otilm.core.security.authz.SecurityFilter;
import com.fasterxml.jackson.core.JsonProcessingException;

import java.util.List;
import java.util.Map;
import java.util.UUID;

public interface SecretInternalService extends ResourceExtensionService {

    /**
     * Batch lookup of the latest-version fingerprint for each given secret.
     */
    Map<UUID, String> getLatestFingerprintsByUuid(List<UUID> secretUuids);

    void approvalCreatedAction(UUID resourceUuid) throws NotFoundException;

    void processSecretAction(ActionMessage actionMessage, boolean hasApproval, boolean isApproved) throws ConnectorException, NotFoundException, AttributeException, JsonProcessingException, SecretOperationException;

    Long statisticsSecretCount(SecurityFilter filter);

    StatisticsDto addSecretStatistics(SecurityFilter filter, StatisticsDto dto);
}
