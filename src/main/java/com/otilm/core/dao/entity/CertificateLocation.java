package com.otilm.core.dao.entity;

import com.otilm.api.model.common.attribute.common.BaseAttribute;
import com.otilm.core.util.AttributeDefinitionUtils;
import jakarta.persistence.Column;
import jakarta.persistence.EmbeddedId;
import jakarta.persistence.Entity;
import jakarta.persistence.FetchType;
import jakarta.persistence.ManyToOne;
import jakarta.persistence.MapsId;
import jakarta.persistence.Table;
import java.io.Serializable;
import java.time.OffsetDateTime;
import java.util.List;
import java.util.Objects;
import lombok.Getter;
import lombok.RequiredArgsConstructor;
import lombok.Setter;
import lombok.ToString;
import org.hibernate.proxy.HibernateProxy;

@Getter
@Setter
@ToString
@RequiredArgsConstructor
@Entity
@Table(name = "certificate_location")
public class CertificateLocation implements Serializable {

    @EmbeddedId
    private CertificateLocationId id = new CertificateLocationId();

    @ManyToOne(fetch = FetchType.LAZY)
    @MapsId("locationUuid")
    @ToString.Exclude
    private Location location;

    @ManyToOne(fetch = FetchType.LAZY)
    @MapsId("certificateUuid")
    @ToString.Exclude
    private Certificate certificate;

    @Column(name = "push_attributes")
    private String pushAttributes;

    @Column(name = "csr_attributes")
    private String csrAttributes;

    @Column(name = "with_key")
    private boolean withKey;

    public List<BaseAttribute> getPushAttributes() {
        return AttributeDefinitionUtils.deserialize(pushAttributes, BaseAttribute.class);
    }

    public void setPushAttributes(List<BaseAttribute> pushAttributes) {
        this.pushAttributes = AttributeDefinitionUtils.serialize(pushAttributes);
    }

    public List<BaseAttribute> getCsrAttributes() {
        return AttributeDefinitionUtils.deserialize(csrAttributes, BaseAttribute.class);
    }

    public void setCsrAttributes(List<BaseAttribute> csrAttributes) {
        this.csrAttributes = AttributeDefinitionUtils.serialize(csrAttributes);
    }

    public OffsetDateTime getCreated() {
        return certificate.getCreated();
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
        CertificateLocation that = (CertificateLocation) o;
        return getId() != null && Objects.equals(getId(), that.getId());
    }

    @Override
    public final int hashCode() {
        return Objects.hash(id);
    }
}
