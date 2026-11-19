package com.otilm.core.service;

import com.otilm.api.model.core.auth.ProtectedResourceMetadataDto;

public interface ProtectedResourceMetadataExternalService {

    /**
     * Get the metadata an unauthenticated client reads to find the authorization servers that issue tokens for the API.
     *
     * @return {@link com.otilm.api.model.core.auth.ProtectedResourceMetadataDto} built for the current request
     */
    ProtectedResourceMetadataDto getProtectedResourceMetadata();
}
