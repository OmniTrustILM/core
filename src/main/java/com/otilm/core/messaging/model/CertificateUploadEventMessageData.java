package com.otilm.core.messaging.model;

import com.otilm.api.model.client.attribute.RequestAttribute;
import lombok.Builder;

import java.util.List;

@Builder
public record CertificateUploadEventMessageData(
        List<RequestAttribute> customAttributes,
        String certificateContent
) {
}
