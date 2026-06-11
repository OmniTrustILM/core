package com.otilm.core.dao.entity.acme;

import com.otilm.api.model.common.NameAndUuidDto;
import com.otilm.api.model.core.acme.AcmeProfileDto;
import com.otilm.api.model.core.acme.AcmeProfileListDto;
import com.otilm.core.dao.entity.ProtocolCertificateAssociations;
import com.otilm.core.dao.entity.RaProfile;
import com.otilm.core.dao.entity.UniquelyIdentifiedAndAudited;
import com.otilm.core.service.acme.AcmeConstants;
import com.otilm.core.util.DtoMapper;
import com.otilm.core.util.ObjectAccessControlMapper;
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
@Table(name = "acme_profile")
public class AcmeProfile extends UniquelyIdentifiedAndAudited implements Serializable, DtoMapper<AcmeProfileDto>, ObjectAccessControlMapper<NameAndUuidDto> {

    @Column(name = "name")
    private String name;

    @Column(name = "description")
    private String description;

    @Column(name = "is_enabled")
    private Boolean isEnabled;

    @Column(name = "terms_of_service_url")
    private String termsOfServiceUrl;

    @Column(name = "dns_resolver_ip")
    private String dnsResolverIp;

    @Column(name = "dns_resolver_port")
    private String dnsResolverPort;

    @OneToOne(fetch = FetchType.LAZY)
    @JsonBackReference
    @JoinColumn(name = "ra_profile_uuid", insertable = false, updatable = false)
    @ToString.Exclude
    private RaProfile raProfile;

    @Column(name = "ra_profile_uuid")
    private UUID raProfileUuid;

    @Column(name = "website_url")
    private String website;

    @Column(name = "validity")
    private Integer validity;

    @Column(name = "retry_interval")
    private Integer retryInterval;

    @Column(name = "disable_new_orders")
    private Boolean disableNewOrders;

    @Column(name = "terms_of_service_change_url")
    private String termsOfServiceChangeUrl;

    @Column(name = "require_contact")
    private Boolean requireContact;

    @Column(name = "require_terms_of_service")
    private Boolean requireTermsOfService;

    @Column(name = "certificate_associations_uuid")
    private UUID certificateAssociationsUuid;

    @OneToOne(fetch = FetchType.LAZY, orphanRemoval = true)
    @JoinColumn(name = "certificate_associations_uuid", insertable = false, updatable = false)
    @JsonBackReference
    @ToString.Exclude
    private ProtocolCertificateAssociations certificateAssociations;

    @Override
    public AcmeProfileDto mapToDto() {
        AcmeProfileDto acmeProfileDto = new AcmeProfileDto();
        if (raProfile != null) {
            acmeProfileDto.setRaProfile(raProfile.mapToDtoSimplified());
        }
        acmeProfileDto.setDescription(description);
        acmeProfileDto.setEnabled(isEnabled);
        acmeProfileDto.setName(name);
        acmeProfileDto.setUuid(uuid.toString());
        acmeProfileDto.setDnsResolverIp(dnsResolverIp);
        acmeProfileDto.setDnsResolverPort(dnsResolverPort);
        acmeProfileDto.setRetryInterval(retryInterval);
        acmeProfileDto.setTermsOfServiceChangeDisable(disableNewOrders);
        acmeProfileDto.setTermsOfServiceUrl(termsOfServiceUrl);
        acmeProfileDto.setValidity(validity);
        acmeProfileDto.setRequireContact(requireContact);
        acmeProfileDto.setRequireTermsOfService(requireTermsOfService);
        acmeProfileDto.setWebsiteUrl(website);
        acmeProfileDto.setTermsOfServiceChangeUrl(termsOfServiceChangeUrl);
        if (raProfile != null) {
            acmeProfileDto.setDirectoryUrl(ServletUriComponentsBuilder.fromCurrentContextPath().build().toUriString() + AcmeConstants.ACME_URI_HEADER + "/" + name + "/directory");
        }
        return acmeProfileDto;
    }

    public AcmeProfileListDto mapToDtoSimple() {
        AcmeProfileListDto acmeProfileDto = new AcmeProfileListDto();
        if (raProfile != null) {
            acmeProfileDto.setRaProfile(raProfile.mapToDtoSimplified());
        }
        acmeProfileDto.setDescription(description);
        acmeProfileDto.setEnabled(isEnabled);
        acmeProfileDto.setName(name);
        acmeProfileDto.setUuid(uuid.toString());
        if (raProfile != null) {
            acmeProfileDto.setDirectoryUrl(ServletUriComponentsBuilder.fromCurrentContextPath().build().toUriString()
                    + AcmeConstants.ACME_URI_HEADER + "/" + name + "/directory");
        }
        return acmeProfileDto;
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

    public Boolean isDisableNewOrders() {
        return disableNewOrders;
    }

    public Boolean isRequireContact() {
        return requireContact;
    }

    public Boolean isRequireTermsOfService() {
        return requireTermsOfService;
    }

    @Override
    public final boolean equals(Object o) {
        if (this == o) return true;
        if (o == null) return false;
        Class<?> oEffectiveClass = o instanceof HibernateProxy ? ((HibernateProxy) o).getHibernateLazyInitializer().getPersistentClass() : o.getClass();
        Class<?> thisEffectiveClass = this instanceof HibernateProxy ? ((HibernateProxy) this).getHibernateLazyInitializer().getPersistentClass() : this.getClass();
        if (thisEffectiveClass != oEffectiveClass) return false;
        AcmeProfile that = (AcmeProfile) o;
        return getUuid() != null && Objects.equals(getUuid(), that.getUuid());
    }

    @Override
    public final int hashCode() {
        return this instanceof HibernateProxy ? ((HibernateProxy) this).getHibernateLazyInitializer().getPersistentClass().hashCode() : getClass().hashCode();
    }
}
