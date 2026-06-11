package com.otilm.core.dao.entity;

import jakarta.persistence.Column;
import jakarta.persistence.EntityListeners;
import jakarta.persistence.MappedSuperclass;
import lombok.*;
import org.hibernate.annotations.CreationTimestamp;
import org.hibernate.annotations.UpdateTimestamp;
import org.springframework.data.annotation.CreatedBy;
import org.springframework.data.annotation.LastModifiedBy;
import org.springframework.data.jpa.domain.support.AuditingEntityListener;

import java.time.OffsetDateTime;

@Getter
@Setter
@ToString
@RequiredArgsConstructor
@MappedSuperclass
@EntityListeners(AuditingEntityListener.class)
public abstract class Audited {

    @Column(name = "i_author")
    @CreatedBy
    @LastModifiedBy
    protected String author;

    @Column(name = "i_cre", nullable = false, updatable = false)
    @CreationTimestamp
    protected OffsetDateTime created;

    @Column(name = "i_upd", nullable = false)
    @UpdateTimestamp
    protected OffsetDateTime updated;

}
