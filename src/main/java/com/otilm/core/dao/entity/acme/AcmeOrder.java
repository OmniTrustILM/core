package com.otilm.core.dao.entity.acme;

import com.otilm.api.model.core.acme.Order;
import com.otilm.api.model.core.acme.OrderStatus;
import com.otilm.core.dao.entity.Certificate;
import com.otilm.core.dao.entity.UniquelyIdentifiedAndAudited;
import com.otilm.core.service.acme.AcmeConstants;
import com.otilm.core.util.AcmeCommonHelper;
import com.otilm.core.util.DtoMapper;
import com.otilm.core.util.SerializationUtil;
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
@Table(name = "acme_order")
public class AcmeOrder extends UniquelyIdentifiedAndAudited implements Serializable, DtoMapper<Order> {

    @Column(name="order_id")
    private String orderId;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "account_uuid", nullable = false, insertable = false, updatable = false)
    @ToString.Exclude
    private AcmeAccount acmeAccount;

    @Column(name = "account_uuid")
    private UUID acmeAccountUuid;

    @OneToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "certificate_ref", insertable = false, updatable = false)
    @ToString.Exclude
    private Certificate certificateReference;

    @Column(name = "certificate_ref")
    private UUID certificateReferenceUuid;

    @Column(name="certificate_id")
    private String certificateId;

    @Column(name="not_before")
    private Date notBefore;

    @Column(name="not_after")
    private Date notAfter;

    @Column(name="expires")
    private Date expires;

    @Column(name="identifiers")
    private String identifiers;

    @Column(name="status")
    @Enumerated(EnumType.STRING)
    private OrderStatus status;

    @JsonBackReference
    @OneToMany(mappedBy = "order", fetch = FetchType.LAZY)
    @ToString.Exclude
    private Set<AcmeAuthorization> authorizations = new HashSet<>();

    @Override
    public Order mapToDto(){
        Order order = new Order();
        order.setAuthorizations(authorizations.stream().map(AcmeAuthorization::getUrl).collect(Collectors.toList()));
        order.setFinalize(getFinalizeUrl());
        order.setStatus(status);
        if (status.equals(OrderStatus.VALID)) {
            order.setCertificate(getCertificateUrl());
        }
        order.setExpires(AcmeCommonHelper.getStringFromDate(expires));
        order.setNotAfter(AcmeCommonHelper.getStringFromDate(notAfter));
        order.setNotBefore(AcmeCommonHelper.getStringFromDate(notBefore));
        order.setIdentifiers(SerializationUtil.deserializeIdentifiers(identifiers));
        return order;
    }

    public void setAcmeAccount(AcmeAccount acmeAccount) {
        this.acmeAccount = acmeAccount;
        this.acmeAccountUuid = acmeAccount.getUuid();
    }

    public void setCertificateReference(Certificate certificateReference) {
        this.certificateReference = certificateReference;
        if(certificateReference != null) this.certificateReferenceUuid = certificateReference.getUuid();
    }

    // Custom Getter for Order
    private String getBaseUrl() {
        if(ServletUriComponentsBuilder.fromCurrentRequestUri().build().toUriString().contains("/raProfile/")){
            return ServletUriComponentsBuilder.fromCurrentContextPath().build().toUriString()
                    + AcmeConstants.ACME_URI_HEADER + "/raProfile/"
                    + acmeAccount.getRaProfile().getName();
        }
        return ServletUriComponentsBuilder.fromCurrentContextPath().build().toUriString()
                + AcmeConstants.ACME_URI_HEADER + "/"
                + acmeAccount.getAcmeProfile().getName();
    }

    public String getUrl() {
        return getBaseUrl() + "/order/" + orderId;
    }

    // Custom Getter for Certificate URL
    public String getCertificateUrl() {
        return getBaseUrl() + "/cert/" + certificateId;
    }

    // Custom Getter for Finalize URL
    public String getFinalizeUrl() {
        return getBaseUrl() + "/order/" + orderId + "/finalize";
    }

    @Override
    public final boolean equals(Object o) {
        if (this == o) return true;
        if (o == null) return false;
        Class<?> oEffectiveClass = o instanceof HibernateProxy ? ((HibernateProxy) o).getHibernateLazyInitializer().getPersistentClass() : o.getClass();
        Class<?> thisEffectiveClass = this instanceof HibernateProxy ? ((HibernateProxy) this).getHibernateLazyInitializer().getPersistentClass() : this.getClass();
        if (thisEffectiveClass != oEffectiveClass) return false;
        AcmeOrder acmeOrder = (AcmeOrder) o;
        return getUuid() != null && Objects.equals(getUuid(), acmeOrder.getUuid());
    }

    @Override
    public final int hashCode() {
        return this instanceof HibernateProxy ? ((HibernateProxy) this).getHibernateLazyInitializer().getPersistentClass().hashCode() : getClass().hashCode();
    }
}
