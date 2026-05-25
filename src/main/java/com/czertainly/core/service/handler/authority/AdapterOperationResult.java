package com.czertainly.core.service.handler.authority;

import com.czertainly.api.model.common.attribute.common.MetadataAttribute;
import com.czertainly.api.model.core.certificate.CertificateType;
import org.springframework.lang.Nullable;

import java.util.List;

/**
 * Unified return type for adapter operation methods (issue, renew, revoke, register).
 * Outcome discriminates sync 200 / sync 204 / async 202.
 *
 * <p>Known constraint: closed record shape. If a future v4 introduces partial-progress
 * or intermediate-certificate semantics, refactor to a sealed interface.</p>
 */
public record AdapterOperationResult(
    AdapterOperationOutcome outcome,
    @Nullable String certificateData,
    @Nullable List<MetadataAttribute> meta,
    @Nullable CertificateType certificateType
) {
    public boolean isAsync() { return outcome == AdapterOperationOutcome.ASYNC_ACCEPTED; }

    public static AdapterOperationResult syncOk(String data, List<MetadataAttribute> meta, CertificateType type) {
        return new AdapterOperationResult(AdapterOperationOutcome.SYNC_OK, data, meta, type);
    }

    public static AdapterOperationResult syncNoContent() {
        return new AdapterOperationResult(AdapterOperationOutcome.SYNC_NO_CONTENT, null, null, null);
    }

    public static AdapterOperationResult asyncAccepted(List<MetadataAttribute> meta) {
        return new AdapterOperationResult(AdapterOperationOutcome.ASYNC_ACCEPTED, null, meta, null);
    }
}
