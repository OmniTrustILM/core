package com.otilm.core.messaging.model;

import com.otilm.api.model.core.auth.Resource;
import com.otilm.core.service.handler.authority.CertificateOperation;

import java.util.UUID;

/**
 * A request to poll the status of one in-flight async authority operation.
 *
 * <p>{@code resourceType} is always {@link Resource#CERTIFICATE} today and is not read by the listener;
 * it is a deliberate discriminator so other provider interfaces can share the {@code provider.status-poll}
 * queue for their own resources later without changing the message contract.</p>
 */
public record CertificateStatusPollMessage(
        Resource resourceType,
        UUID resourceUuid,
        CertificateOperation op,
        int attempt
) {}
