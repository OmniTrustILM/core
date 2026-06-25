package com.otilm.core.dao.entity.scep;

import com.otilm.api.model.common.NameAndUuidDto;
import com.otilm.api.model.core.scep.ScepProfileDetailDto;
import com.otilm.api.model.core.scep.ScepProfileDto;
import com.otilm.core.dao.entity.Certificate;
import com.otilm.core.dao.entity.ProtocolCertificateAssociations;
import com.otilm.core.dao.entity.RaProfile;
import com.otilm.core.dao.entity.UniquelyIdentifiedAndAudited;
import com.otilm.core.service.model.Securable;
import com.otilm.core.service.scep.impl.ScepServiceImpl;
import com.otilm.core.util.DtoMapper;
import com.otilm.core.util.ObjectAccessControlMapper;
import com.otilm.core.util.SecretEncodingVersion;
import com.otilm.core.util.SecretsUtil;
import com.fasterxml.jackson.annotation.JsonBackReference;
import jakarta.persistence.*;
import lombok.*;
import org.hibernate.proxy.HibernateProxy;
import org.springframework.web.servlet.support.ServletUriComponentsBuilder;

import java.io.Serializable;
import java.util.Objects;
import java.util.UUID;

@Getter
@Setter
@ToString
@RequiredArgsConstructor
@Entity
@Table(name = "scep_profile")
public class ScepProfile extends UniquelyIdentifiedAndAudited implements Serializable, DtoMapper<ScepProfileDto>, ObjectAccessControlMapper<NameAndUuidDto>, Securable {

    @Column(name = "name")
    private String name;

    @Column(name = "description")
    private String description;

    @Column(name = "enabled")
    private Boolean isEnabled;

    @Column(name = "require_manual_approval")
    private Boolean requireManualApproval;

    @OneToOne(fetch = FetchType.LAZY)
    @JsonBackReference
    @JoinColumn(name = "ra_profile_uuid", insertable = false, updatable = false)
    @ToString.Exclude
    private RaProfile raProfile;

    @Column(name = "ra_profile_uuid")
    private UUID raProfileUuid;

    @OneToOne(fetch = FetchType.LAZY)
    @JsonBackReference
    @JoinColumn(name = "ca_certificate_uuid", insertable = false, updatable = false)
    @ToString.Exclude
    private Certificate caCertificate;

    @Column(name = "ca_certificate_uuid")
    private UUID caCertificateUuid;

    @Column(name = "renew_threshold")
    private Integer renewalThreshold;

    @Column(name = "include_ca_certificate")
    private boolean includeCaCertificate = false;

    @Column(name = "include_ca_certificate_chain")
    private boolean includeCaCertificateChain = false;

    @Column(name = "challenge_password")
    private String challengePassword;

    @Column(name = "intune_enabled")
    private boolean intuneEnabled;

    @Column(name = "intune_tenant")
    private String intuneTenant;

    @Column(name = "intune_application_id")
    private String intuneApplicationId;

    @Column(name = "intune_application_key")
    private String intuneApplicationKey;

    @Column(name = "certificate_associations_uuid")
    private UUID certificateAssociationsUuid;

    @OneToOne(fetch = FetchType.LAZY, orphanRemoval = true)
    @JoinColumn(name = "certificate_associations_uuid", insertable = false, updatable = false)
    @JsonBackReference
    @ToString.Exclude
    private ProtocolCertificateAssociations certificateAssociations;

    @Override
    public ScepProfileDto mapToDto() {
        ScepProfileDto scepProfileDto = new ScepProfileDto();
        if (raProfile != null) {
            scepProfileDto.setRaProfile(raProfile.mapToDtoSimplified());
            scepProfileDto.setScepUrl(ServletUriComponentsBuilder.fromCurrentContextPath().build().toUriString()
                    + ScepServiceImpl.SCEP_URL_PREFIX + "/" + name + "/pkiclient.exe");
        }
        scepProfileDto.setDescription(description);
        scepProfileDto.setEnabled(isEnabled);
        scepProfileDto.setName(name);
        scepProfileDto.setUuid(uuid.toString());
        scepProfileDto.setIncludeCaCertificate(includeCaCertificate);
        scepProfileDto.setIncludeCaCertificateChain(includeCaCertificateChain);
        scepProfileDto.setRenewThreshold(renewalThreshold);
        scepProfileDto.setEnableIntune(intuneEnabled);
        scepProfileDto.setEnableChallengePassword(challengePassword != null);
        return scepProfileDto;
    }

    public ScepProfileDetailDto mapToDetailDto() {
        ScepProfileDetailDto scepProfileDto = new ScepProfileDetailDto();
        if (raProfile != null) {
            scepProfileDto.setRaProfile(raProfile.mapToDtoSimplified());
        }
        scepProfileDto.setDescription(description);
        scepProfileDto.setEnabled(isEnabled);
        scepProfileDto.setName(name);
        scepProfileDto.setUuid(uuid.toString());
        scepProfileDto.setIncludeCaCertificate(includeCaCertificate);
        scepProfileDto.setIncludeCaCertificateChain(includeCaCertificateChain);
        scepProfileDto.setRenewThreshold(renewalThreshold);
        if (caCertificate != null) scepProfileDto.setCaCertificate(caCertificate.mapToListDto());
        if (raProfile != null) {
            scepProfileDto.setScepUrl(ServletUriComponentsBuilder.fromCurrentContextPath().build().toUriString()
                    + ScepServiceImpl.SCEP_URL_PREFIX + "/" + name + "/pkiclient.exe");
        }
        scepProfileDto.setEnableIntune(intuneEnabled);
        scepProfileDto.setEnableChallengePassword(challengePassword != null);
        scepProfileDto.setIntuneTenant(intuneTenant);
        scepProfileDto.setIntuneApplicationId(intuneApplicationId);
        // Custom Attributes for the DTO should be set in the methods which require the detail DTO
        return scepProfileDto;
    }

    @Override
    public NameAndUuidDto mapToAccessControlObjects() {
        return new NameAndUuidDto(uuid.toString(), name);
    }

    public Boolean isEnabled() {
        return isEnabled;
    }

    public void setEnabled(Boolean enabled) {
        isEnabled = enabled;
    }

    public void setRaProfile(RaProfile raProfile) {
        this.raProfile = raProfile;
        if (raProfile != null) this.raProfileUuid = raProfile.getUuid();
        else this.raProfileUuid = null;
    }

    public void setCaCertificate(Certificate caCertificate) {
        this.caCertificate = caCertificate;
        if (caCertificate != null) this.setCaCertificateUuid(caCertificate.getUuid());
    }

    public String getChallengePassword() {
        if (challengePassword != null) {
            return SecretsUtil.decodeAndDecryptSecretString(challengePassword, SecretEncodingVersion.V1);
        }
        return null;
    }

    public void setChallengePassword(String challengePassword) {
        if (challengePassword != null) {
            this.challengePassword = SecretsUtil.encryptAndEncodeSecretString(challengePassword, SecretEncodingVersion.V1);
        } else {
            this.challengePassword = null;
        }
    }

    @Override
    public final boolean equals(Object o) {
        if (this == o) return true;
        if (o == null) return false;
        Class<?> oEffectiveClass = o instanceof HibernateProxy proxy ? proxy.getHibernateLazyInitializer().getPersistentClass() : o.getClass();
        Class<?> thisEffectiveClass = this instanceof HibernateProxy proxy ? proxy.getHibernateLazyInitializer().getPersistentClass() : this.getClass();
        if (thisEffectiveClass != oEffectiveClass) return false;
        ScepProfile that = (ScepProfile) o;
        return getUuid() != null && Objects.equals(getUuid(), that.getUuid());
    }

    @Override
    public final int hashCode() {
        return this instanceof HibernateProxy proxy ? proxy.getHibernateLazyInitializer().getPersistentClass().hashCode() : getClass().hashCode();
    }
}
