package com.otilm.core.dao.entity;

import jakarta.persistence.Column;
import jakarta.persistence.EntityListeners;
import jakarta.persistence.MappedSuperclass;
import java.time.OffsetDateTime;
import lombok.Getter;
import lombok.RequiredArgsConstructor;
import lombok.Setter;
import lombok.ToString;
import org.hibernate.annotations.CreationTimestamp;
import org.hibernate.annotations.UpdateTimestamp;
import org.springframework.data.annotation.AccessType;
import org.springframework.data.annotation.CreatedBy;
import org.springframework.data.annotation.LastModifiedBy;
import org.springframework.data.jpa.domain.support.AuditingEntityListener;

@Getter
@Setter
@ToString
@RequiredArgsConstructor
@MappedSuperclass
@EntityListeners(AuditingEntityListener.class)
public abstract class Audited {

    // Auditing sets the author through the setter, which bytecode dirty tracking records; a direct field write would
    // leave the column out of a @DynamicUpdate entity's update.
    @Column(name = "i_author")
    @CreatedBy
    @LastModifiedBy
    @AccessType(AccessType.Type.PROPERTY)
    protected String author;

    @Column(name = "i_cre", nullable = false, updatable = false)
    @CreationTimestamp
    protected OffsetDateTime created;

    @Column(name = "i_upd", nullable = false)
    @UpdateTimestamp
    protected OffsetDateTime updated;

}
