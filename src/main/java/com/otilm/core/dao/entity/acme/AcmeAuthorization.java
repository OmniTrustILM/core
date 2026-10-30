package com.otilm.core.dao.entity.acme;

import com.fasterxml.jackson.annotation.JsonBackReference;
import com.otilm.api.model.core.acme.Authorization;
import com.otilm.api.model.core.acme.AuthorizationStatus;
import com.otilm.core.dao.entity.UniquelyIdentifiedAndAudited;
import com.otilm.core.service.acme.AcmeConstants;
import com.otilm.core.util.AcmeCommonHelper;
import com.otilm.core.util.DtoMapper;
import com.otilm.core.util.SerializationUtil;
import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.EnumType;
import jakarta.persistence.Enumerated;
import jakarta.persistence.FetchType;
import jakarta.persistence.JoinColumn;
import jakarta.persistence.ManyToOne;
import jakarta.persistence.OneToMany;
import jakarta.persistence.Table;
import java.io.Serializable;
import java.util.Date;
import java.util.HashSet;
import java.util.Objects;
import java.util.Set;
import java.util.UUID;
import java.util.stream.Collectors;
import lombok.Getter;
import lombok.RequiredArgsConstructor;
import lombok.Setter;
import lombok.ToString;
import org.hibernate.proxy.HibernateProxy;
import org.springframework.web.servlet.support.ServletUriComponentsBuilder;

@Getter
@Setter
@ToString
@RequiredArgsConstructor
@Entity
@Table(name = "acme_authorization")
public class AcmeAuthorization extends UniquelyIdentifiedAndAudited implements Serializable, DtoMapper<Authorization> {

    @Column(name = "authorization_id")
    private String authorizationId;

    @Column(name = "identifier")
    private String identifier;

    @Column(name = "status")
    @Enumerated(EnumType.STRING)
    private AuthorizationStatus status;

    @Column(name = "expires")
    private Date expires;

    @JsonBackReference
    @OneToMany(mappedBy = "authorization", fetch = FetchType.LAZY)
    @ToString.Exclude
    private Set<AcmeChallenge> challenges = new HashSet<>();

    @Column(name = "wildcard")
    private Boolean wildcard;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "order_uuid", nullable = false, insertable = false, updatable = false)
    @ToString.Exclude
    private AcmeOrder order;

    @Column(name = "order_uuid", nullable = false)
    private UUID orderUuid;

    @Override
    public Authorization mapToDto() {

        Authorization authorization = new Authorization();
        authorization.setStatus(status);
        authorization.setExpires(AcmeCommonHelper.getStringFromDate(expires));
        authorization.setIdentifier(SerializationUtil.deserializeIdentifier(identifier));
        authorization.setChallenges(challenges.stream().map(AcmeChallenge::mapToDto).collect(Collectors.toList()));
        return authorization;
    }

    public void setOrder(AcmeOrder order) {
        this.order = order;
        this.orderUuid = order.getUuid();
    }

    private String getBaseUrl() {
        if (ServletUriComponentsBuilder.fromCurrentRequestUri().build().toUriString().contains("/raProfile/")) {
            return ServletUriComponentsBuilder.fromCurrentContextPath().build().toUriString()
                    + AcmeConstants.ACME_URI_HEADER + "/raProfile/" + order.getAcmeAccount().getRaProfile().getName();
        }
        return ServletUriComponentsBuilder.fromCurrentContextPath().build().toUriString()
                + AcmeConstants.ACME_URI_HEADER + "/" + order.getAcmeAccount().getAcmeProfile().getName();
    }

    // Custom Getter for Authorization URL
    public String getUrl() {
        return getBaseUrl() + "/authz/" + authorizationId;
    }

    @Override
    public final boolean equals(Object o) {
        if (this == o) {
            return true;
        }
        if (o == null) {
            return false;
        }
        Class<?> oEffectiveClass = o instanceof HibernateProxy
                ? ((HibernateProxy) o).getHibernateLazyInitializer().getPersistentClass()
                : o.getClass();
        Class<?> thisEffectiveClass = this instanceof HibernateProxy
                ? ((HibernateProxy) this).getHibernateLazyInitializer().getPersistentClass()
                : this.getClass();
        if (thisEffectiveClass != oEffectiveClass) {
            return false;
        }
        AcmeAuthorization that = (AcmeAuthorization) o;
        return getUuid() != null && Objects.equals(getUuid(), that.getUuid());
    }

    @Override
    public final int hashCode() {
        return this instanceof HibernateProxy
                ? ((HibernateProxy) this).getHibernateLazyInitializer().getPersistentClass().hashCode()
                : getClass().hashCode();
    }
}
