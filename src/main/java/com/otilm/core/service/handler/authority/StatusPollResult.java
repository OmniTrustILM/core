package com.otilm.core.service.handler.authority;

import com.otilm.api.model.common.attribute.common.MetadataAttribute;
import com.otilm.api.model.connector.v3.certificate.CertificateOperationStatus;
import org.springframework.lang.Nullable;

import java.util.List;

public record StatusPollResult(
    CertificateOperationStatus status,
    @Nullable String certificateData,
    @Nullable List<MetadataAttribute> meta,
    @Nullable String reason
) {}
