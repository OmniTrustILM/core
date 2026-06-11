package com.otilm.core.dao.entity.notifications;

import com.otilm.api.model.client.notification.NotificationDto;
import com.otilm.api.model.core.auth.Resource;
import com.otilm.core.dao.entity.UniquelyIdentified;
import jakarta.persistence.*;
import lombok.*;

import java.util.*;

@Setter
@Getter
@ToString
@RequiredArgsConstructor
@Entity
@Table(name = "notification")
public class Notification extends UniquelyIdentified {

    @Column(name = "message", nullable = false)
    private String message;

    @Column(name = "detail")
    private String detail;

    @Column(name = "sent_at", nullable = false, columnDefinition = "TIMESTAMP default CURRENT_TIMESTAMP")
    private Date sentAt = new Date();

    @Column(name = "target_object_type")
    @Enumerated(EnumType.STRING)
    private Resource targetObjectType;

    @Column(name = "target_object_identification")
    private String targetObjectIdentification;

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
