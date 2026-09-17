package com.otilm.core.dao.entity;

import com.fasterxml.jackson.annotation.JsonBackReference;
import com.otilm.core.model.NamedModel;
import jakarta.persistence.CascadeType;
import jakarta.persistence.Column;
import jakarta.persistence.ConstraintMode;
import jakarta.persistence.Entity;
import jakarta.persistence.FetchType;
import jakarta.persistence.ForeignKey;
import jakarta.persistence.JoinColumn;
import jakarta.persistence.JoinTable;
import jakarta.persistence.ManyToMany;
import jakarta.persistence.ManyToOne;
import jakarta.persistence.OneToMany;
import jakarta.persistence.OneToOne;
import jakarta.persistence.Table;
import java.io.Serializable;
import java.util.HashSet;
import java.util.Objects;
import java.util.Set;
import java.util.UUID;
import lombok.Getter;
import lombok.RequiredArgsConstructor;
import lombok.Setter;
import lombok.ToString;
import org.hibernate.annotations.SQLJoinTableRestriction;
import org.hibernate.proxy.HibernateProxy;

@Getter
@Setter
@ToString
@RequiredArgsConstructor
@Entity
@Table(name = "cryptographic_key")
public class CryptographicKey extends UniquelyIdentifiedAndAudited implements Serializable, NamedModel {

    @Override
    public UUID uuid() {
        return getUuid();
    }

    @Override
    public String name() {
        return getName();
    }

    @Column(name = "name")
    private String name;

    @Column(name = "description")
    private String description;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "token_profile_uuid", insertable = false, updatable = false)
    @ToString.Exclude
    private TokenProfile tokenProfile;

    @Column(name = "token_profile_uuid")
    private UUID tokenProfileUuid;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "token_instance_uuid", insertable = false, updatable = false)
    @ToString.Exclude
    private TokenInstanceReference tokenInstanceReference;

    @Column(name = "token_instance_uuid")
    private UUID tokenInstanceReferenceUuid;

    @ManyToMany(fetch = FetchType.LAZY)
    @JoinTable(name = "group_association",
            joinColumns = @JoinColumn(name = "object_uuid", referencedColumnName = "uuid", insertable = false,
                    updatable = false, foreignKey = @ForeignKey(ConstraintMode.NO_CONSTRAINT)),
            inverseJoinColumns = @JoinColumn(name = "group_uuid", insertable = false, updatable = false))
    @SQLJoinTableRestriction("resource = 'CRYPTOGRAPHIC_KEY'")
    @ToString.Exclude
    private Set<Group> groups = new HashSet<>();

    @OneToOne(fetch = FetchType.LAZY, mappedBy = "key")
    @ToString.Exclude
    private OwnerAssociation owner;

    @JsonBackReference
    @OneToMany(mappedBy = "key", cascade = CascadeType.ALL, fetch = FetchType.LAZY)
    @ToString.Exclude
    private Set<CryptographicKeyItem> items = new HashSet<>();

    @JsonBackReference
    @OneToMany(mappedBy = "key", fetch = FetchType.LAZY)
    @ToString.Exclude
    private Set<Certificate> certificates = new HashSet<>();

    @JsonBackReference
    @OneToMany(mappedBy = "altKey", fetch = FetchType.LAZY)
    @ToString.Exclude
    private Set<Certificate> altCertificates = new HashSet<>();

    public void setTokenProfile(TokenProfile tokenProfile) {
        this.tokenProfile = tokenProfile;
        if (tokenProfile != null) {
            this.tokenProfileUuid = tokenProfile.getUuid();
        }
    }

    public void setTokenInstanceReference(TokenInstanceReference tokenInstanceReference) {
        this.tokenInstanceReference = tokenInstanceReference;
        if (tokenInstanceReference != null) {
            this.tokenInstanceReferenceUuid = tokenInstanceReference.getUuid();
        }
    }

    @Override
    public final boolean equals(Object o) {
        if (this == o) {
            return true;
        }
        if (o == null) {
            return false;
        }
        Class<?> oEffectiveClass = o instanceof HibernateProxy proxy
                ? proxy.getHibernateLazyInitializer().getPersistentClass()
                : o.getClass();
        Class<?> thisEffectiveClass = this instanceof HibernateProxy proxy
                ? proxy.getHibernateLazyInitializer().getPersistentClass()
                : this.getClass();
        if (thisEffectiveClass != oEffectiveClass) {
            return false;
        }
        if (!(o instanceof CryptographicKey that)) {
            return false;
        }
        return getUuid() != null && Objects.equals(getUuid(), that.getUuid());
    }

    @Override
    public final int hashCode() {
        return this instanceof HibernateProxy proxy
                ? proxy.getHibernateLazyInitializer().getPersistentClass().hashCode()
                : getClass().hashCode();
    }
}
