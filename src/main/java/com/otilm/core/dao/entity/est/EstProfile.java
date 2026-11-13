package com.otilm.core.dao.entity.est;

import com.otilm.api.model.core.est.EstAuthenticationPolicy;
import com.otilm.core.dao.entity.ProtocolCertificateAssociations;
import com.otilm.core.dao.entity.RaProfile;
import com.otilm.core.dao.entity.TokenProfile;
import com.otilm.core.dao.entity.UniquelyIdentifiedAndAudited;
import com.otilm.core.service.model.Securable;
import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.EnumType;
import jakarta.persistence.Enumerated;
import jakarta.persistence.FetchType;
import jakarta.persistence.JoinColumn;
import jakarta.persistence.ManyToOne;
import jakarta.persistence.OneToOne;
import jakarta.persistence.Table;
import jakarta.persistence.UniqueConstraint;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;
import lombok.Getter;
import lombok.Setter;
import lombok.ToString;
import org.hibernate.annotations.JdbcTypeCode;
import org.hibernate.type.SqlTypes;

@Getter
@Setter
@Entity
@Table(name = "est_profile", uniqueConstraints = @UniqueConstraint(columnNames = "name"))
public class EstProfile extends UniquelyIdentifiedAndAudited implements Securable {

    @Getter(onMethod_ = {@Override})
    @Column(name = "name", nullable = false)
    private String name;

    @Column(name = "description")
    private String description;

    @Column(name = "enabled", nullable = false)
    private boolean enabled;

    @Column(name = "system_default", nullable = false)
    private boolean systemDefault;

    @Column(name = "ra_profile_uuid")
    private UUID raProfileUuid;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "ra_profile_uuid", insertable = false, updatable = false)
    @ToString.Exclude
    private RaProfile raProfile;

    @Column(name = "authentication_policy", nullable = false)
    @Enumerated(EnumType.STRING)
    private EstAuthenticationPolicy authenticationPolicy;

    @Column(name = "basic_credential_secret_uuids", nullable = false)
    @JdbcTypeCode(SqlTypes.ARRAY)
    private List<UUID> basicCredentialSecretUuids = new ArrayList<>();

    @Column(name = "trusted_ca_certificate_uuids", nullable = false)
    @JdbcTypeCode(SqlTypes.ARRAY)
    private List<UUID> trustedCaCertificateUuids = new ArrayList<>();

    @Column(name = "allow_renewal", nullable = false)
    private boolean allowRenewal = true;

    @Column(name = "allow_rekey", nullable = false)
    private boolean allowRekey = true;

    @Column(name = "renewal_threshold")
    private Integer renewalThreshold;

    @Column(name = "server_key_generation", nullable = false)
    private boolean serverKeyGeneration;

    @Column(name = "issue_wait_timeout", nullable = false)
    private int issueWaitTimeout = 10;

    @Column(name = "retry_after", nullable = false)
    private int retryAfter = 30;

    @Column(name = "server_key_generation_timeout", nullable = false)
    private int serverKeyGenerationTimeout = 30;

    @Column(name = "key_recovery", nullable = false)
    private boolean keyRecovery;

    @Column(name = "key_recovery_token_profile_uuid")
    private UUID keyRecoveryTokenProfileUuid;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "key_recovery_token_profile_uuid", insertable = false, updatable = false)
    @ToString.Exclude
    private TokenProfile keyRecoveryTokenProfile;

    @Column(name = "key_recovery_key_attributes", length = Integer.MAX_VALUE)
    private String keyRecoveryKeyAttributes;

    @Column(name = "certificate_associations_uuid")
    private UUID certificateAssociationsUuid;

    @OneToOne(fetch = FetchType.LAZY, orphanRemoval = true)
    @JoinColumn(name = "certificate_associations_uuid", insertable = false, updatable = false)
    @ToString.Exclude
    private ProtocolCertificateAssociations certificateAssociations;

    public void setRaProfile(RaProfile raProfile) {
        this.raProfile = raProfile;
        this.raProfileUuid = raProfile != null ? raProfile.getUuid() : null;
    }

    public void setKeyRecoveryTokenProfile(TokenProfile keyRecoveryTokenProfile) {
        this.keyRecoveryTokenProfile = keyRecoveryTokenProfile;
        this.keyRecoveryTokenProfileUuid = keyRecoveryTokenProfile != null ? keyRecoveryTokenProfile.getUuid() : null;
    }

    public void setCertificateAssociations(ProtocolCertificateAssociations certificateAssociations) {
        this.certificateAssociations = certificateAssociations;
        this.certificateAssociationsUuid = certificateAssociations != null ? certificateAssociations.getUuid() : null;
    }

    @Override
    public boolean equals(Object o) {
        return super.equals(o);
    }

    @Override
    public int hashCode() {
        return super.hashCode();
    }
}
