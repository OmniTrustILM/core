package com.otilm.core.service.handler.authority;

import com.otilm.api.model.common.attribute.common.MetadataAttribute;
import com.otilm.api.model.connector.v3.certificate.CertificateOperationStatus;
import java.util.List;
import org.springframework.lang.Nullable;

/**
 * A connector's answer to a status poll.
 *
 * @param reasonQuotesSentSecret whether the reason quotes a secret value the poll sent, so that only operators, who may
 * see what the connector holds, may read it
 */
public record StatusPollResult(CertificateOperationStatus status, @Nullable String certificateData,
        @Nullable List<MetadataAttribute> meta, @Nullable String reason, boolean reasonQuotesSentSecret) {

    public StatusPollResult(CertificateOperationStatus status, @Nullable String certificateData,
            @Nullable List<MetadataAttribute> meta, @Nullable String reason) {
        this(status, certificateData, meta, reason, false);
    }

    /**
     * The reason as the requester of the operation may read it, or null when the connector gave none or it quotes a
     * secret the poll sent.
     */
    @Nullable
    public String requesterReason() {
        return reasonQuotesSentSecret ? null : reason;
    }
}
