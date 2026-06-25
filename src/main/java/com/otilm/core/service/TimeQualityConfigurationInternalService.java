package com.otilm.core.service;

import com.otilm.api.exception.NotFoundException;
import com.otilm.core.model.signing.timequality.TimeQualityConfigurationModel;

import java.util.UUID;

public interface TimeQualityConfigurationInternalService extends ResourceExtensionService {

    /**
     * Returns the cached model for the given UUID.
     */
    TimeQualityConfigurationModel getTimeQualityConfigurationModel(UUID uuid) throws NotFoundException;
}
