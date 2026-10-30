package com.otilm.core.dao.entity.notifications;

import com.otilm.api.model.core.other.ResourceEvent;
import com.otilm.core.dao.entity.ResourceObjectAssociation;
import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.EnumType;
import jakarta.persistence.Enumerated;
import jakarta.persistence.FetchType;
import jakarta.persistence.JoinColumn;
import jakarta.persistence.ManyToOne;
import jakarta.persistence.Table;
import jakarta.persistence.UniqueConstraint;
import java.time.OffsetDateTime;
import java.util.UUID;
import lombok.Getter;
import lombok.RequiredArgsConstructor;
import lombok.Setter;
import lombok.ToString;
import org.hibernate.annotations.UpdateTimestamp;

@Getter
@Setter
@ToString
@RequiredArgsConstructor
@Entity
@Table(name = "pending_notification",
        uniqueConstraints = @UniqueConstraint(name = PendingNotification.UNIQUE_SUPPRESSION_ROW_CONSTRAINT,
                columnNames = {"notification_profile_uuid", "resource", "object_uuid", "event"}))
public class PendingNotification extends ResourceObjectAssociation {

    public static final String UNIQUE_SUPPRESSION_ROW_CONSTRAINT = "uq_pending_notification_suppression_row";

    @Column(name = "notification_profile_uuid", nullable = false)
    private UUID notificationProfileUuid;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "notification_profile_uuid", insertable = false, updatable = false)
    @ToString.Exclude
    private NotificationProfile notificationProfile;

    @Column(name = "version", nullable = false)
    private int version;

    @Column(name = "event")
    @Enumerated(EnumType.STRING)
    private ResourceEvent event;

    @UpdateTimestamp
    @Column(name = "last_sent_at", nullable = false)
    private OffsetDateTime lastSentAt;

    @Column(name = "repetitions", nullable = false)
    private int repetitions;

    @Override
    public boolean equals(Object o) {
        return super.equals(o);
    }

    @Override
    public int hashCode() {
        return super.hashCode();
    }

}
