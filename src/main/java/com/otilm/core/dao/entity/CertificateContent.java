package com.otilm.core.dao.entity;

import com.fasterxml.jackson.annotation.JsonIgnore;
import jakarta.persistence.*;
import lombok.*;
import org.hibernate.annotations.ColumnDefault;
import org.hibernate.proxy.HibernateProxy;

import java.io.Serializable;
import java.util.HashSet;
import java.util.Objects;
import java.util.Set;

@Getter
@Setter
@ToString
@RequiredArgsConstructor
@Entity
@Table(name = "certificate_content")
public class CertificateContent implements Serializable {

    @Id
    @Column(name = "id")
    @ColumnDefault("nextval('certificate_content_id_seq'::regclass)")
    @GeneratedValue(strategy = GenerationType.SEQUENCE, generator = "certificate_content_seq")
    @SequenceGenerator(name = "certificate_content_seq", sequenceName = "certificate_content_id_seq", allocationSize = 1)
    private Long id;

    @Column(name = "fingerprint", unique = true)
    private String fingerprint;

    @Column(name = "content", length = Integer.MAX_VALUE)
    private String content;

    @OneToMany(mappedBy = "certificateContent", fetch = FetchType.LAZY)
    @JsonIgnore
    @ToString.Exclude
    private Set<DiscoveryCertificate> discoveryCertificates = new HashSet<>();

    @OneToOne(mappedBy = "certificateContent")
    @JsonIgnore
    @ToString.Exclude
    private Certificate certificate;

    @Override
    public final boolean equals(Object o) {
        if (this == o) return true;
        if (o == null) return false;
        Class<?> oEffectiveClass = o instanceof HibernateProxy ? ((HibernateProxy) o).getHibernateLazyInitializer().getPersistentClass() : o.getClass();
        Class<?> thisEffectiveClass = this instanceof HibernateProxy ? ((HibernateProxy) this).getHibernateLazyInitializer().getPersistentClass() : this.getClass();
        if (thisEffectiveClass != oEffectiveClass) return false;
        CertificateContent that = (CertificateContent) o;
        return getId() != null && Objects.equals(getId(), that.getId());
    }

    @Override
    public final int hashCode() {
        return this instanceof HibernateProxy ? ((HibernateProxy) this).getHibernateLazyInitializer().getPersistentClass().hashCode() : getClass().hashCode();
    }
}
