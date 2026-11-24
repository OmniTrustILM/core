package com.otilm.core.dao.entity;

import com.otilm.api.model.client.trustedcertificate.TrustedCertificatePlatformState;
import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.EnumType;
import jakarta.persistence.Enumerated;
import jakarta.persistence.FetchType;
import jakarta.persistence.JoinColumn;
import jakarta.persistence.OneToOne;
import jakarta.persistence.Table;
import java.time.OffsetDateTime;
import java.util.UUID;
import lombok.Getter;
import lombok.Setter;
import lombok.ToString;
import org.hibernate.annotations.Check;
import org.hibernate.annotations.DynamicUpdate;

/**
 * What ILM trusts an inventory certificate for, and what the platform last reported about it.
 *
 * <p>
 * {@code validation} and {@code platform} are the intent an administrator set. A row with both false exists only while
 * {@code platformRemovalPending} is set: the platform was asked to drop the certificate and has not confirmed it yet.
 * The {@code platformState} columns hold the last observed platform state, never intent.
 */
@Getter
@Setter
@Entity
@Table(name = "trusted_certificate")
@Check(name = "ck_trusted_certificate_purpose", constraints = "validation OR platform OR platform_removal_pending")
// Intent and observation are written by different actors; a save writes only the columns it changed.
@DynamicUpdate
public class TrustedCertificate extends UniquelyIdentified {

    @Column(name = "certificate_uuid", nullable = false, unique = true)
    private UUID certificateUuid;

    // Trust is X.509 only, and the list shows the DNs and SANs only that subclass maps.
    @ToString.Exclude
    @OneToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "certificate_uuid", insertable = false, updatable = false)
    private X509CertificateEntity certificate;

    @Column(name = "validation", nullable = false)
    private boolean validation;

    @Column(name = "platform", nullable = false)
    private boolean platform;

    @Column(name = "platform_removal_pending", nullable = false)
    private boolean platformRemovalPending;

    @Column(name = "platform_uuid", length = 36)
    private String platformUuid;

    @Enumerated(EnumType.STRING)
    @Column(name = "platform_state", columnDefinition = "TEXT")
    private TrustedCertificatePlatformState platformState;

    @Column(name = "platform_state_message", columnDefinition = "TEXT")
    private String platformStateMessage;

    @Column(name = "platform_state_checked_at")
    private OffsetDateTime platformStateCheckedAt;

    @Column(name = "created_at", nullable = false)
    private OffsetDateTime createdAt;

    @Column(name = "updated_at", nullable = false)
    private OffsetDateTime updatedAt;

    // No-op overrides required by S2160: identity and hashing stay UUID-based, and the added columns never affect
    // equality.
    @Override
    public boolean equals(Object o) {
        return super.equals(o);
    }

    @Override
    public int hashCode() {
        return super.hashCode();
    }
}
