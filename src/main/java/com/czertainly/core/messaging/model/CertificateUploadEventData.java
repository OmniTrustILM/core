package com.czertainly.core.messaging.model;

import com.czertainly.api.model.client.attribute.RequestAttributeDto;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

import java.util.List;
import java.util.UUID;

@Getter
@Setter
@NoArgsConstructor
public class CertificateUploadEventData {

    private String certificateContent;
    private List<RequestAttributeDto> customAttributes;
    private UUID userUuid;
}
