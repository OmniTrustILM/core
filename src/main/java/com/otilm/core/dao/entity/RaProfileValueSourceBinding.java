package com.otilm.core.dao.entity;

import jakarta.persistence.*;
import lombok.*;
import org.hibernate.proxy.HibernateProxy;

import java.util.Objects;
import java.util.UUID;

/**
 * Value-source binding onto a dynamically fetched connector definition.
 */
@Getter
@Setter
@ToString
@RequiredArgsConstructor
@Entity
@Table(name = "ra_profile_value_source_binding")
public class RaProfileValueSourceBinding extends UniquelyIdentified {

    @Column(name = "ra_profile_uuid", nullable = false)
    private UUID raProfileUuid;

    @Column(name = "attribute_uuid")
    private String attributeUuid;

    @Column(name = "attribute_name")
    private String attributeName;

    @Column(name = "value_source_kind", nullable = false)
    private String valueSourceType;

    @Column(name = "collection_ref")
    private String collectionRef;

    @Column(name = "params", length = Integer.MAX_VALUE)
    private String params;

    @Override
    public final boolean equals(Object o) {
        if (this == o) return true;
        if (o == null) return false;
        Class<?> oEffectiveClass = o instanceof HibernateProxy proxy ? proxy.getHibernateLazyInitializer().getPersistentClass() : o.getClass();
        Class<?> thisEffectiveClass = this instanceof HibernateProxy proxy ? proxy.getHibernateLazyInitializer().getPersistentClass() : this.getClass();
        if (thisEffectiveClass != oEffectiveClass) return false;
        RaProfileValueSourceBinding that = (RaProfileValueSourceBinding) o;
        return getUuid() != null && Objects.equals(getUuid(), that.getUuid());
    }

    @Override
    public final int hashCode() {
        return this instanceof HibernateProxy proxy ? proxy.getHibernateLazyInitializer().getPersistentClass().hashCode() : getClass().hashCode();
    }
}
