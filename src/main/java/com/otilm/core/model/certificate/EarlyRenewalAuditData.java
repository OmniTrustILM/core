package com.otilm.core.model.certificate;

import com.otilm.api.model.core.certificate.EarlyRenewalRequestDto;
import java.io.Serializable;

/** What an early renewal request asked for, as the audit record keeps it. */
public record EarlyRenewalAuditData(Long spreadSeconds, String explanationUrl) implements Serializable {

    public static EarlyRenewalAuditData of(EarlyRenewalRequestDto request) {
        return new EarlyRenewalAuditData(request.getSpreadSeconds(), request.getExplanationUrl());
    }
}
