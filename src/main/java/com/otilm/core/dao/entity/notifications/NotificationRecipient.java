package com.otilm.core.dao.entity.notifications;

import com.otilm.core.dao.entity.UniquelyIdentified;
import jakarta.persistence.*;
import lombok.*;

import java.util.Date;
import java.util.UUID;

@Getter
@Setter
@ToString
@RequiredArgsConstructor
@Entity
@Table(name = "notification_recipient", uniqueConstraints = {@UniqueConstraint(columnNames = {"notification_uuid", "user_uuid"})})
public class NotificationRecipient extends UniquelyIdentified {

    @Column(name = "notification_uuid", nullable = false)
    private UUID notificationUuid;

    @Column(name = "user_uuid", nullable = false)
    private UUID userUuid;

    @Column(name = "read_at")
    private Date readAt;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "notification_uuid", insertable = false, updatable = false, nullable = false)
    @ToString.Exclude
    private Notification notification;

    @Override
    public boolean equals(Object o) {
        return super.equals(o);
    }

    @Override
    public int hashCode() {
        return super.hashCode();
    }
}
