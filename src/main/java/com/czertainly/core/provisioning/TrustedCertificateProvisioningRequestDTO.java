package com.czertainly.core.provisioning;

import jakarta.validation.constraints.NotNull;
import org.apache.commons.lang3.builder.ToStringBuilder;
import org.apache.commons.lang3.builder.ToStringStyle;

import java.util.Arrays;

/**
 * Request for creating a new trusted certificate in provisioning service.
 *
 * @param certificateContent Raw certificate content serialized as Base64 String in JSON
 */
public record TrustedCertificateProvisioningRequestDTO(
        @NotNull
        byte[] certificateContent
) {
    // Overridden so byte[] is compared by content, not by reference (the default record
    // implementation falls back to Object.equals() / identity hashCode for arrays).

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (!(o instanceof TrustedCertificateProvisioningRequestDTO that)) return false;
        return Arrays.equals(certificateContent, that.certificateContent);
    }

    @Override
    public int hashCode() {
        return Arrays.hashCode(certificateContent);
    }

    // certificateContent is rendered as its length only — typical certs are 1–2 KB and
    // dumping the raw bytes into logs is noise (and may end up in audit/error sinks).
    @Override
    public String toString() {
        return new ToStringBuilder(this, ToStringStyle.SHORT_PREFIX_STYLE)
                .append("certificateContent", certificateContent == null ? "null" : "byte[" + certificateContent.length + "]")
                .toString();
    }
}
