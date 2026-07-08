package com.otilm.core.dao.entity;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.EnumType;
import jakarta.persistence.Enumerated;
import jakarta.persistence.Table;
import jakarta.persistence.UniqueConstraint;
import lombok.Getter;
import lombok.Setter;
import lombok.ToString;

import java.time.OffsetDateTime;
import java.util.UUID;

/**
 * Durable authorization for a pre-registered certificate: the challenge, issuance window, failed-attempt lockout,
 * and lifecycle state used to authorize a later renew or rekey.
 *
 * <p>Unlike the transient {@link CertificateRegistration} register-to-issue binding, which is cleared once the
 * certificate is first issued, this record survives issuance so it can authorize follow-up operations.
 */
@Getter
@Setter
@ToString
@Entity
// A certificate has at most one durable authorization record.
@Table(name = "certificate_registration_authorization",
        uniqueConstraints = @UniqueConstraint(name = "uq_certificate_registration_authorization_certificate",
                columnNames = "certificate_uuid"))
public class CertificateRegistrationAuthorization extends UniquelyIdentifiedAndAudited {

    @Column(name = "certificate_uuid", nullable = false)
    private UUID certificateUuid;

    // Ciphertext only; the plaintext challenge never touches the entity (see RegistrationChallengeStore).
    // Excluded from toString because a tracing aspect records entity toString into spans.
    @ToString.Exclude
    @Column(name = "challenge", nullable = false, length = Integer.MAX_VALUE)
    private String challenge;

    // Null means no issuance deadline.
    @Column(name = "expires_at")
    private OffsetDateTime expiresAt;

    @Column(name = "failed_attempts", nullable = false)
    private int failedAttempts;

    @Enumerated(EnumType.STRING)
    @Column(name = "state", nullable = false)
    private RegistrationState state;

    @Override
    public boolean equals(Object o) {
        return super.equals(o);
    }

    @Override
    public int hashCode() {
        return super.hashCode();
    }
}
