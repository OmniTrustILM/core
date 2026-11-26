package com.otilm.core.service.handler.authority;

import com.otilm.api.model.connector.v3.certificate.CertificateRenewalInfoResponseDto;

/** The outcome of one renewal information request to a connector. */
public sealed interface RenewalInfoCallResult {

    /** The connector processed the batch; the response holds one result per item. */
    record Answered(CertificateRenewalInfoResponseDto response) implements RenewalInfoCallResult {
    }

    /** The batch failed for now: the request was refused, or the connector or its transport failed. */
    record BackOff(String reason) implements RenewalInfoCallResult {
    }

    /** The connector offers no renewal information, whatever it advertises, so asking is pointless for a while. */
    record Suspend(String authority, String reason) implements RenewalInfoCallResult {
    }
}
