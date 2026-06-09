package com.czertainly.core.dao.entity.acme;

import com.otilm.api.model.core.acme.Authorization;
import com.otilm.api.model.core.acme.AuthorizationStatus;
import com.czertainly.core.dao.entity.UniquelyIdentifiedAndAudited;
import com.czertainly.core.service.acme.AcmeConstants;
import com.czertainly.core.util.AcmeCommonHelper;
import com.czertainly.core.util.DtoMapper;
import com.czertainly.core.util.SerializationUtil;
import com.fasterxml.jackson.annotation.JsonBackReference;
import jakarta.persistence.*;
import lombok.*;
import org.hibernate.proxy.HibernateProxy;
import org.springframework.web.servlet.support.ServletUriComponentsBuilder;

import java.io.Serializable;
import java.util.*;
import java.util.stream.Collectors;

@Getter
@Setter
@ToString
@RequiredArgsConstructor
@Entity
@Table(name = "acme_authorization")
public class AcmeAuthorization  extends UniquelyIdentifiedAndAudited implements Serializable, DtoMapper<Authorization> {

    @Column(name="authorization_id")
    private String authorizationId;

    @Column(name="identifier")
    private String identifier;

    @Column(name="status")
    @Enumerated(EnumType.STRING)
    private AuthorizationStatus status;

    @Column(name = "expires")
    private Date expires;

    @JsonBackReference
    @OneToMany(mappedBy = "authorization", fetch = FetchType.LAZY)
    @ToString.Exclude
    private Set<AcmeChallenge> challenges = new HashSet<>();

    @Column(name="wildcard")
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
        if(ServletUriComponentsBuilder.fromCurrentRequestUri().build().toUriString().contains("/raProfile/")){
            return ServletUriComponentsBuilder.fromCurrentContextPath().build().toUriString()
                    + AcmeConstants.ACME_URI_HEADER + "/raProfile/"
                    + order.getAcmeAccount().getRaProfile().getName();
        }
        return ServletUriComponentsBuilder.fromCurrentContextPath().build().toUriString()
                + AcmeConstants.ACME_URI_HEADER + "/"
                + order.getAcmeAccount().getAcmeProfile().getName();
    }

    // Custom Getter for Authorization URL
    public String getUrl() {
        return getBaseUrl() + "/authz/" + authorizationId;
    }

    @Override
    public final boolean equals(Object o) {
        if (this == o) return true;
        if (o == null) return false;
        Class<?> oEffectiveClass = o instanceof HibernateProxy ? ((HibernateProxy) o).getHibernateLazyInitializer().getPersistentClass() : o.getClass();
        Class<?> thisEffectiveClass = this instanceof HibernateProxy ? ((HibernateProxy) this).getHibernateLazyInitializer().getPersistentClass() : this.getClass();
        if (thisEffectiveClass != oEffectiveClass) return false;
        AcmeAuthorization that = (AcmeAuthorization) o;
        return getUuid() != null && Objects.equals(getUuid(), that.getUuid());
    }

    @Override
    public final int hashCode() {
        return this instanceof HibernateProxy ? ((HibernateProxy) this).getHibernateLazyInitializer().getPersistentClass().hashCode() : getClass().hashCode();
    }
}
