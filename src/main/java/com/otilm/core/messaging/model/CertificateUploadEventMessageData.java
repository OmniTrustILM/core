package com.otilm.core.messaging.model;

import com.otilm.api.model.client.attribute.RequestAttribute;
import java.util.List;
import lombok.Builder;

@Builder
public record CertificateUploadEventMessageData(List<RequestAttribute> customAttributes, String certificateContent) {
}
