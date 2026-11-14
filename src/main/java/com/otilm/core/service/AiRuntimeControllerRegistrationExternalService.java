package com.otilm.core.service;

import org.springframework.http.ResponseEntity;

/** Fixed controller-owned role observations; neither operation enables runtime business execution. */
public interface AiRuntimeControllerRegistrationExternalService {
    ResponseEntity<byte[]> observeRunGateway();

    ResponseEntity<byte[]> observeManagementGateway();
}
