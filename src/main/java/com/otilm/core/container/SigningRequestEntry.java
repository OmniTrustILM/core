package com.otilm.core.container;

import com.otilm.api.model.client.inspection.InspectedEntryKind;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;

/**
 * A certificate request the file holds.
 *
 * @param reference the lowercase hex SHA-256 of the request's DER
 * @param request the request
 */
public record SigningRequestEntry(String reference, PKCS10CertificationRequest request) implements ContainerEntry {

    @Override
    public InspectedEntryKind kind() {
        return InspectedEntryKind.SIGNING_REQUEST;
    }
}
