package com.otilm.core.dao.entity.notifications;

import com.otilm.api.model.client.notification.NotificationProfileDetailDto;
import com.otilm.api.model.client.notification.NotificationProfileDto;
import com.otilm.api.model.common.NameAndUuidDto;
import com.otilm.api.model.core.notification.RecipientType;
import com.otilm.core.dao.entity.UniquelyIdentified;
import jakarta.persistence.*;
import lombok.Getter;
import org.hibernate.annotations.JdbcTypeCode;
import org.hibernate.type.SqlTypes;
import lombok.RequiredArgsConstructor;
import lombok.Setter;
import lombok.ToString;
import org.hibernate.annotations.CreationTimestamp;

import java.time.Duration;
import java.time.OffsetDateTime;
import java.util.List;
import java.util.UUID;

@Getter
@Setter
@ToString
@RequiredArgsConstructor
@Entity
@Table(name = "notification_profile_version")
public class NotificationProfileVersion extends UniquelyIdentified {

    @Column(name = "notification_profile_uuid", nullable = false)
    private UUID notificationProfileUuid;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "notification_profile_uuid", insertable = false, updatable = false)
    @ToString.Exclude
    private NotificationProfile notificationProfile;

    @Column(name = "version", nullable = false)
    private int version;

    @Column(name = "recipient_type", nullable = false)
    @Enumerated(EnumType.STRING)
    private RecipientType recipientType;

    @Column(name = "recipient_uuids")
    @JdbcTypeCode(SqlTypes.ARRAY)
    private List<UUID> recipientUuids;

    @Column(name = "notification_instance_ref_uuid")
    private UUID notificationInstanceRefUuid;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "notification_instance_ref_uuid", referencedColumnName = "uuid", insertable = false, updatable = false)
    @ToString.Exclude
    private NotificationInstanceReference notificationInstance;

    @Column(name = "internal_notification", nullable = false)
    private boolean internalNotification;

    @Column(name = "frequency", columnDefinition = "interval")
    private Duration frequency;

    @Column(name = "repetitions")
    private Integer repetitions;

    @Column(name = "created_at", nullable = false, updatable = false)
    @CreationTimestamp
    protected OffsetDateTime createdAt;

    public NotificationProfileDto mapToDto() {
        final NotificationProfileDto notificationProfileDto = new NotificationProfileDto();
        notificationProfileDto.setUuid(this.getNotificationProfile().getUuid().toString());
        notificationProfileDto.setName(this.getNotificationProfile().getName());
        notificationProfileDto.setDescription(this.getNotificationProfile().getDescription());
        notificationProfileDto.setVersion(this.version);
        notificationProfileDto.setRecipientType(this.recipientType);
        notificationProfileDto.setRecipientUuids(this.recipientUuids);
        notificationProfileDto.setNotificationInstanceUuid(this.notificationInstanceRefUuid);
        notificationProfileDto.setInternalNotification(this.internalNotification);

        return notificationProfileDto;
    }

    public NotificationProfileDetailDto mapToDetailDto(List<NameAndUuidDto> recipients) {
        final NotificationProfileDetailDto notificationProfileDetailDto = new NotificationProfileDetailDto();
        notificationProfileDetailDto.setUuid(this.getNotificationProfile().getUuid().toString());
        notificationProfileDetailDto.setName(this.getNotificationProfile().getName());
        notificationProfileDetailDto.setDescription(this.getNotificationProfile().getDescription());
        notificationProfileDetailDto.setVersion(this.version);
        notificationProfileDetailDto.setRecipientType(this.recipientType);
        notificationProfileDetailDto.setRecipients(recipients);
        notificationProfileDetailDto.setNotificationInstance(this.notificationInstance == null ? null : new NameAndUuidDto(notificationInstance.getUuid().toString(), notificationInstance.getName()));
        notificationProfileDetailDto.setInternalNotification(this.internalNotification);
        notificationProfileDetailDto.setFrequency(this.frequency);
        notificationProfileDetailDto.setRepetitions(this.repetitions);

        return notificationProfileDetailDto;
    }

    @Override
    public boolean equals(Object o) {
        return super.equals(o);
    }

    @Override
    public int hashCode() {
        return super.hashCode();
    }

}
