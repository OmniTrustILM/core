package com.otilm.core.dao.entity.notifications;

import com.otilm.api.model.client.notification.NotificationDto;
import com.otilm.api.model.core.auth.Resource;
import com.otilm.core.dao.entity.UniquelyIdentified;
import com.otilm.core.mapper.notifications.NotificationMapper;
import com.otilm.core.model.notification.NotificationSubject;
import jakarta.persistence.CascadeType;
import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.EnumType;
import jakarta.persistence.Enumerated;
import jakarta.persistence.FetchType;
import jakarta.persistence.OneToMany;
import jakarta.persistence.Table;
import java.util.Date;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import lombok.Getter;
import lombok.RequiredArgsConstructor;
import lombok.Setter;
import lombok.ToString;
import org.hibernate.annotations.JdbcTypeCode;
import org.hibernate.type.SqlTypes;

@Setter
@Getter
@ToString
@RequiredArgsConstructor
@Entity
@Table(name = "notification")
public class Notification extends UniquelyIdentified {

    @Column(name = "message", nullable = false, columnDefinition = "TEXT")
    private String message;

    @Column(name = "detail", columnDefinition = "TEXT")
    private String detail;

    @Column(name = "sent_at", nullable = false, columnDefinition = "TIMESTAMP default CURRENT_TIMESTAMP")
    private Date sentAt = new Date();

    @Column(name = "target_object_type")
    @Enumerated(EnumType.STRING)
    private Resource targetObjectType;

    @Column(name = "target_object_identification")
    private String targetObjectIdentification;

    // S1948: entities are Serializable through UniquelyIdentifiedObject, but nothing Java-serializes them - Jackson
    // owns the persistence shape of this JSONB field.
    @SuppressWarnings("java:S1948")
    @Column(name = "subject", columnDefinition = "jsonb")
    @JdbcTypeCode(SqlTypes.JSON)
    private NotificationSubject subject;

    @OneToMany(fetch = FetchType.LAZY, mappedBy = "notification", cascade = CascadeType.ALL, orphanRemoval = true)
    @ToString.Exclude
    private Set<NotificationRecipient> notificationRecipients;

    public NotificationDto mapToDto() {
        Optional<NotificationRecipient> notificationRecipient = this.notificationRecipients.stream().findFirst();

        NotificationDto dto = new NotificationDto();
        dto.setUuid(this.getUuid());
        dto.setMessage(this.message);
        dto.setDetail(this.detail);
        dto.setSentAt(this.sentAt);
        dto.setTargetObjectType(this.targetObjectType);
        NotificationMapper.applySubject(dto, this.subject);
        if (this.targetObjectIdentification != null) {
            dto.setTargetObjectIdentification(List.of(this.targetObjectIdentification.split(",")));
        }
        notificationRecipient.ifPresent(recipient -> dto.setReadAt(recipient.getReadAt()));
        return dto;
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
