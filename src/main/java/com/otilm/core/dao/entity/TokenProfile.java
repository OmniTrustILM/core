package com.otilm.core.dao.entity;

import com.fasterxml.jackson.annotation.JsonBackReference;
import com.otilm.api.model.common.NameAndUuidDto;
import com.otilm.api.model.common.enums.BitMaskEnum;
import com.otilm.api.model.core.cryptography.key.KeyUsage;
import com.otilm.core.service.model.Securable;
import com.otilm.core.util.ObjectAccessControlMapper;
import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.FetchType;
import jakarta.persistence.JoinColumn;
import jakarta.persistence.ManyToOne;
import jakarta.persistence.Table;
import java.io.Serializable;
import java.util.EnumSet;
import java.util.List;
import java.util.Objects;
import java.util.UUID;
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
@Table(name = "token_profile")
public class TokenProfile extends UniquelyIdentifiedAndAudited
        implements
            Serializable,
            Securable,
            ObjectAccessControlMapper<NameAndUuidDto> {

    @Column(name = "name")
    private String name;

    @Column(name = "description")
    private String description;

    @Column(name = "token_instance_name")
    private String tokenInstanceName;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "token_instance_ref_uuid", insertable = false, updatable = false)
    @ToString.Exclude
    @JsonBackReference
    private TokenInstanceReference tokenInstanceReference;

    @Column(name = "token_instance_ref_uuid")
    private UUID tokenInstanceReferenceUuid;

    @Column(name = "enabled")
    private Boolean enabled;

    @Column(name = "usage")
    private int usage;

    public void setTokenInstanceReference(TokenInstanceReference tokenInstanceReference) {
        this.tokenInstanceReference = tokenInstanceReference;
        if (tokenInstanceReference != null) {
            this.tokenInstanceReferenceUuid = tokenInstanceReference.getUuid();
        }
    }

    public List<KeyUsage> getUsage() {
        return KeyUsage.convertBitMaskToSet(usage).stream().toList();
    }

    public void setUsage(List<KeyUsage> usage) {
        this.usage = BitMaskEnum
                .convertSetToBitMask(usage.isEmpty() ? EnumSet.noneOf(KeyUsage.class) : EnumSet.copyOf(usage));
    }

    @Override
    public NameAndUuidDto mapToAccessControlObjects() {
        return new NameAndUuidDto(uuid.toString(), name);
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
        TokenProfile that = (TokenProfile) o;
        return getUuid() != null && Objects.equals(getUuid(), that.getUuid());
    }

    @Override
    public final int hashCode() {
        return this instanceof HibernateProxy
                ? ((HibernateProxy) this).getHibernateLazyInitializer().getPersistentClass().hashCode()
                : getClass().hashCode();
    }
}
