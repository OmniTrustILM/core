package com.czertainly.core.provisioning;

import org.apache.commons.lang3.builder.ToStringBuilder;
import org.apache.commons.lang3.builder.ToStringStyle;

import java.time.LocalDateTime;
import java.util.Arrays;
import java.util.Objects;

/**
 * Response DTO for trusted certificate from provisioning service.
 *
 * @param uuid               UUID of the trusted certificate
 * @param certificateContent Raw certificate content serialized as Base64 String in JSON
 * @param issuer             Certificate issuer DN
 * @param san                Subject alternative names
 * @param serialNumber       Certificate serial number
 * @param subject            Certificate subject DN
 * @param thumbprint         Certificate thumbprint (fingerprint)
 * @param notBefore          Certificate validity start date
 * @param notAfter           Certificate expiration date
 */
public record TrustedCertificateProvisioningDTO(
        String uuid,
        byte[] certificateContent,
        String issuer,
        String san,
        String serialNumber,
        String subject,
        String thumbprint,
        LocalDateTime notBefore,
        LocalDateTime notAfter
) {
    // Overridden so byte[] is compared by content, not by reference (the default record
    // implementation falls back to Object.equals() / identity hashCode for arrays).

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (!(o instanceof TrustedCertificateProvisioningDTO that)) return false;
        return Objects.equals(uuid, that.uuid)
                && Arrays.equals(certificateContent, that.certificateContent)
                && Objects.equals(issuer, that.issuer)
                && Objects.equals(san, that.san)
                && Objects.equals(serialNumber, that.serialNumber)
                && Objects.equals(subject, that.subject)
                && Objects.equals(thumbprint, that.thumbprint)
                && Objects.equals(notBefore, that.notBefore)
                && Objects.equals(notAfter, that.notAfter);
    }

    @Override
    public int hashCode() {
        int result = Objects.hash(uuid, issuer, san, serialNumber, subject, thumbprint, notBefore, notAfter);
        result = 31 * result + Arrays.hashCode(certificateContent);
        return result;
    }

    // certificateContent is rendered as its length only — typical certs are 1–2 KB and
    // dumping the raw bytes into logs is noise (and may end up in audit/error sinks).
    @Override
    public String toString() {
        return new ToStringBuilder(this, ToStringStyle.SHORT_PREFIX_STYLE)
                .append("uuid", uuid)
                .append("certificateContent", certificateContent == null ? "null" : "byte[" + certificateContent.length + "]")
                .append("issuer", issuer)
                .append("san", san)
                .append("serialNumber", serialNumber)
                .append("subject", subject)
                .append("thumbprint", thumbprint)
                .append("notBefore", notBefore)
                .append("notAfter", notAfter)
                .toString();
    }
}
