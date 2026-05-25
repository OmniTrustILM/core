package com.czertainly.core.messaging.model;

import com.czertainly.api.model.client.attribute.RequestAttribute;
import lombok.Builder;

import java.util.List;

@Builder
public record CertificateUploadEventMessageData(
        List<RequestAttribute> customAttributes,
        String certificateContent
) {
}
