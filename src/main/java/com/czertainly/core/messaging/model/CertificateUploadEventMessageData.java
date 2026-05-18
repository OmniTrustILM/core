package com.czertainly.core.messaging.model;

import com.czertainly.api.model.client.attribute.RequestAttribute;
import lombok.Builder;

import java.util.List;
import java.util.UUID;

@Builder
public record CertificateUploadEventMessageData(
        List<RequestAttribute> customAttributes,
        String fingerprint,
        UUID userUuid,
        String certificateContent
) {
}
