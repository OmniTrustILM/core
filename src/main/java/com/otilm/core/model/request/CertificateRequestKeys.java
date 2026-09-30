package com.otilm.core.model.request;

import java.util.UUID;

/**
 * The keys a certificate request's signature attributes belong to, so they are validated and stored under those keys'
 * connectors.
 *
 * @param keyUuid the key that signed the request, or null when none is known
 * @param altKeyUuid the key that signed its alternative signature, or null when none is known
 */
public record CertificateRequestKeys(UUID keyUuid, UUID altKeyUuid) {
}
