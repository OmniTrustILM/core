package com.otilm.core.dao.entity.cmp;

import com.otilm.api.model.common.NameAndUuidDto;
import com.otilm.api.model.core.cmp.CmpProfileDetailDto;
import com.otilm.api.model.core.cmp.CmpProfileDto;
import com.otilm.api.model.core.cmp.CmpProfileVariant;
import com.otilm.api.model.core.cmp.ProtectionMethod;
import com.otilm.core.dao.entity.Certificate;
import com.otilm.core.dao.entity.ProtocolCertificateAssociations;
import com.otilm.core.dao.entity.RaProfile;
import com.otilm.core.dao.entity.UniquelyIdentifiedAndAudited;
import com.otilm.core.service.cmp.CmpConstants;
import com.otilm.core.service.model.Securable;
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
@Table(name = "cmp_profile")
public class CmpProfile extends UniquelyIdentifiedAndAudited implements Serializable, DtoMapper<CmpProfileDto>, ObjectAccessControlMapper<NameAndUuidDto>, Securable {

    @Setter
    @Getter
    @Column(name = "name")
    private String name;

    @Setter
    @Getter
    @Column(name = "description")
    private String description;

    @Setter
    @Getter
    @Column(name = "enabled")
    private Boolean enabled;

    @Setter
    @Getter
    @Column(name = "variant")
    @Enumerated(EnumType.STRING)
    private CmpProfileVariant variant = CmpProfileVariant.V2;

    @Getter
    @OneToOne(fetch = FetchType.LAZY)
    @JsonBackReference
    @JoinColumn(name = "ra_profile_uuid", insertable = false, updatable = false)
    @ToString.Exclude
    private RaProfile raProfile;

    @Setter
    @Getter
    @Column(name = "ra_profile_uuid")
    private UUID raProfileUuid;

    @Setter
    @Getter
    @Column(name = "request_protection_method")
    @Enumerated(EnumType.STRING)
    private ProtectionMethod requestProtectionMethod;

    @Setter
    @Getter
    @Column(name = "response_protection_method")
    @Enumerated(EnumType.STRING)
    private ProtectionMethod responseProtectionMethod;

    @Column(name = "shared_secret")
    private String sharedSecret;

    @Getter
    @OneToOne(fetch = FetchType.LAZY)
    @JsonBackReference
    @JoinColumn(name = "signing_certificate_uuid", insertable = false, updatable = false)
    @ToString.Exclude
    private Certificate signingCertificate;

    @Setter
    @Getter
    @Column(name = "signing_certificate_uuid")
    private UUID signingCertificateUuid;

    @Column(name = "certificate_associations_uuid")
    private UUID certificateAssociationsUuid;

    @OneToOne(fetch = FetchType.LAZY, orphanRemoval = true)
    @JoinColumn(name = "certificate_associations_uuid", insertable = false, updatable = false)
    private ProtocolCertificateAssociations certificateAssociations;

    @Override
    public CmpProfileDto mapToDto() {
        CmpProfileDto cmpProfileDto = new CmpProfileDto();
        setCommonFields(cmpProfileDto);
        return cmpProfileDto;
    }

    public CmpProfileDetailDto mapToDetailDto() {
        CmpProfileDetailDto cmpProfileDto = new CmpProfileDetailDto();
        setCommonFields(cmpProfileDto);
        cmpProfileDto.setRequestProtectionMethod(requestProtectionMethod);
        cmpProfileDto.setResponseProtectionMethod(responseProtectionMethod);

        if (signingCertificate != null) cmpProfileDto.setSigningCertificate(signingCertificate.mapToListDto());

        // Custom Attributes for the DTO should be set in the methods which require the detail DTO
        return cmpProfileDto;
    }

    private void setCommonFields(CmpProfileDto cmpProfileDto) {
        if (raProfile != null) {
            cmpProfileDto.setRaProfile(raProfile.mapToDtoSimplified());
            cmpProfileDto.setCmpUrl(ServletUriComponentsBuilder.fromCurrentContextPath().build().toUriString()
                    + CmpConstants.CMP_BASE_CONTEXT + "/" + name);
        }
        cmpProfileDto.setDescription(description);
        cmpProfileDto.setEnabled(enabled);
        cmpProfileDto.setVariant(variant);
        cmpProfileDto.setName(name);
        cmpProfileDto.setUuid(uuid.toString());
    }

    @Override
    public NameAndUuidDto mapToAccessControlObjects() {
        return new NameAndUuidDto(uuid.toString(), name);
    }

    public void setRaProfile(RaProfile raProfile) {
        this.raProfile = raProfile;
        if (raProfile != null) this.raProfileUuid = raProfile.getUuid();
        else this.raProfileUuid = null;
    }

    public void setSigningCertificate(Certificate signingCertificate) {
        this.signingCertificate = signingCertificate;
        if (signingCertificate != null) this.setSigningCertificateUuid(signingCertificate.getUuid());
    }

    public String getSharedSecret() {
        if (sharedSecret != null) {
            return SecretsUtil.decodeAndDecryptSecretString(sharedSecret, SecretEncodingVersion.V1);
        }
        return null;
    }

    public void setSharedSecret(String sharedSecret) {
        if (sharedSecret != null) {
            this.sharedSecret = SecretsUtil.encryptAndEncodeSecretString(sharedSecret, SecretEncodingVersion.V1);
        } else {
            this.sharedSecret = null;
        }
    }

    @Override
    public final boolean equals(Object o) {
        if (this == o) return true;
        if (o == null) return false;
        Class<?> oEffectiveClass = o instanceof HibernateProxy ? ((HibernateProxy) o).getHibernateLazyInitializer().getPersistentClass() : o.getClass();
        Class<?> thisEffectiveClass = this instanceof HibernateProxy ? ((HibernateProxy) this).getHibernateLazyInitializer().getPersistentClass() : this.getClass();
        if (thisEffectiveClass != oEffectiveClass) return false;
        CmpProfile that = (CmpProfile) o;
        return getUuid() != null && Objects.equals(getUuid(), that.getUuid());
    }

    @Override
    public final int hashCode() {
        return this instanceof HibernateProxy ? ((HibernateProxy) this).getHibernateLazyInitializer().getPersistentClass().hashCode() : getClass().hashCode();
    }
}
