package com.otilm.core.messaging.model;

import com.otilm.api.model.core.auth.Resource;
import com.otilm.core.service.handler.authority.CertificateOperation;

import java.util.UUID;

public record CertificateStatusPollMessage(
        Resource resourceType,
        UUID resourceUuid,
        CertificateOperation op,
        int attempt
) {}
