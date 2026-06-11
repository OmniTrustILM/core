package com.otilm.core.dao.entity;

import com.otilm.core.security.authz.SecuredParentUUID;
import com.otilm.core.security.authz.SecuredUUID;
import jakarta.persistence.Column;
import jakarta.persistence.Id;
import jakarta.persistence.MappedSuperclass;
import jakarta.persistence.PrePersist;
import lombok.*;
import org.hibernate.proxy.HibernateProxy;

import java.util.Objects;
import java.util.UUID;

@Setter
@Getter
@ToString
@RequiredArgsConstructor
@MappedSuperclass
public abstract class UniquelyIdentifiedAndAudited extends Audited implements UniquelyIdentifiedObject {

    @Id
    @Column(name = "uuid", nullable = false, updatable = false)
    public UUID uuid;

    public SecuredUUID getSecuredUuid() {
        return SecuredUUID.fromUUID(uuid);
    }

    public SecuredParentUUID getSecuredParentUuid() {
        return SecuredParentUUID.fromUUID(uuid);
    }

    @PrePersist
    private void generateUuid() {
        if (uuid == null) {
            setUuid(UUID.randomUUID());
        }
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null) return false;
        Class<?> oEffectiveClass = o instanceof HibernateProxy proxy ? proxy.getHibernateLazyInitializer().getPersistentClass() : o.getClass();
        Class<?> thisEffectiveClass = this instanceof HibernateProxy proxy ? proxy.getHibernateLazyInitializer().getPersistentClass() : this.getClass();
        if (thisEffectiveClass != oEffectiveClass) return false;
        UniquelyIdentifiedAndAudited that = (UniquelyIdentifiedAndAudited) o;
        return getUuid() != null && Objects.equals(getUuid(), that.getUuid());
    }

    @Override
    public int hashCode() {
        return this instanceof HibernateProxy proxy ? proxy.getHibernateLazyInitializer().getPersistentClass().hashCode() : getClass().hashCode();
    }
}
