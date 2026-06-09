package com.czertainly.core.dao.entity;

import com.otilm.api.model.core.certificate.CertificateRelationType;
import jakarta.persistence.*;
import lombok.*;
import org.hibernate.annotations.CreationTimestamp;

import java.io.Serializable;
import java.time.OffsetDateTime;

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

