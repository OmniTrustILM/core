package com.otilm.core.dao.entity;

import com.otilm.api.model.core.certificate.CertificateRelationType;
import jakarta.persistence.Column;
import jakarta.persistence.EmbeddedId;
import jakarta.persistence.Entity;
import jakarta.persistence.EnumType;
import jakarta.persistence.Enumerated;
import jakarta.persistence.FetchType;
import jakarta.persistence.ManyToOne;
import jakarta.persistence.MapsId;
import jakarta.persistence.Table;
import java.io.Serializable;
import java.time.OffsetDateTime;
import lombok.Getter;
import lombok.Setter;
import lombok.ToString;
import org.hibernate.annotations.CreationTimestamp;

@Getter
@Setter
@Entity
@Table(name = "certificate_relation")
public class CertificateRelation implements Serializable {

    @EmbeddedId
    private CertificateRelationId id = new CertificateRelationId();

    @ManyToOne(fetch = FetchType.LAZY)
    @MapsId("predecessorCertificateUuid")
    @ToString.Exclude
    private Certificate predecessorCertificate;

    @ManyToOne(fetch = FetchType.LAZY)
    @MapsId("successorCertificateUuid")
    @ToString.Exclude
    private Certificate successorCertificate;

    @Column(name = "relation_type")
    @Enumerated(EnumType.STRING)
    private CertificateRelationType relationType;

    @Column(name = "created_at", nullable = false, updatable = false)
    @CreationTimestamp
    protected OffsetDateTime createdAt;

}
