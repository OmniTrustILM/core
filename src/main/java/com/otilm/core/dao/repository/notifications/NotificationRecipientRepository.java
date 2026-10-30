package com.otilm.core.dao.repository.notifications;

import com.otilm.core.dao.entity.notifications.NotificationRecipient;
import com.otilm.core.model.notification.NotificationListItem;
import java.util.UUID;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.stereotype.Repository;

@Repository
public interface NotificationRecipientRepository extends JpaRepository<NotificationRecipient, UUID> {

    @Query("""
            SELECT new com.otilm.core.model.notification.NotificationListItem(
                n.uuid, n.message, n.detail, nr.readAt, n.sentAt, n.targetObjectType, n.targetObjectIdentification,
                n.subject)
                FROM NotificationRecipient nr
                JOIN Notification n ON n.uuid = nr.notificationUuid
                WHERE nr.userUuid = ?1
                ORDER BY n.sentAt DESC
            """)
    Page<NotificationListItem> findByUserUuid(UUID userUuid, Pageable pageable);

    @Query("""
            SELECT new com.otilm.core.model.notification.NotificationListItem(
                n.uuid, n.message, n.detail, nr.readAt, n.sentAt, n.targetObjectType, n.targetObjectIdentification,
                n.subject)
                FROM NotificationRecipient nr
                JOIN Notification n ON n.uuid = nr.notificationUuid
                WHERE nr.userUuid = ?1 AND nr.readAt IS NULL
                ORDER BY n.sentAt DESC
            """)
    Page<NotificationListItem> findUnreadByUserUuid(UUID userUuid, Pageable pageable);

}
