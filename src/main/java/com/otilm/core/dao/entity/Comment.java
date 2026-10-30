package com.otilm.core.dao.entity;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.FetchType;
import jakarta.persistence.JoinColumn;
import jakarta.persistence.ManyToOne;
import jakarta.persistence.PrePersist;
import jakarta.persistence.Table;
import java.time.OffsetDateTime;
import java.util.UUID;
import lombok.Getter;
import lombok.RequiredArgsConstructor;
import lombok.Setter;
import lombok.ToString;
import org.hibernate.annotations.Check;
import org.hibernate.annotations.OnDelete;
import org.hibernate.annotations.OnDeleteAction;

@Getter
@Setter
@ToString
@RequiredArgsConstructor
@Entity
@Table(name = "comment")
// Mirrors the migration's reply-resolution constraint for the test environment, which generates its schema
// from the entities.
@Check(name = "ck_comment_reply_not_resolved", constraints = "parent_uuid IS NULL"
        + " OR (resolved_at IS NULL AND resolved_by_uuid IS NULL AND resolved_by_username IS NULL)")
public class Comment extends ResourceObjectAssociation {

    @Column(name = "parent_uuid")
    private UUID parentUuid;

    // Mirrors ON DELETE CASCADE from the migration for the test environment, which generates its schema from
    // the entities; the writable column stays the scalar parentUuid above.
    @OnDelete(action = OnDeleteAction.CASCADE)
    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "parent_uuid", insertable = false, updatable = false)
    @ToString.Exclude
    private Comment parent;

    @Column(name = "author_uuid", nullable = false)
    private UUID authorUuid;

    @Column(name = "author_username", nullable = false)
    private String authorUsername;

    @Column(name = "created_at", nullable = false, updatable = false)
    private OffsetDateTime createdAt;

    @Column(name = "body", nullable = false, columnDefinition = "TEXT")
    private String body;

    @Column(name = "resolved_at")
    private OffsetDateTime resolvedAt;

    @Column(name = "resolved_by_uuid")
    private UUID resolvedByUuid;

    @Column(name = "resolved_by_username")
    private String resolvedByUsername;

    @PrePersist
    private void setCreatedAt() {
        if (createdAt == null) {
            createdAt = OffsetDateTime.now();
        }
    }
}
