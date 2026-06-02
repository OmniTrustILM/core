package com.czertainly.core.service.writer;

import com.czertainly.core.dao.repository.notifications.NotificationProfileVersionRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.UUID;

@Service
public class NotificationProfileVersionWriter {

    private final NotificationProfileVersionRepository notificationProfileVersionRepository;

    @Autowired
    public NotificationProfileVersionWriter(NotificationProfileVersionRepository notificationProfileVersionRepository) {
        this.notificationProfileVersionRepository = notificationProfileVersionRepository;
    }

    @Transactional
    public void detachHistoricalInstanceReferencesByNotificationInstanceRefUuid(UUID notificationInstanceRefUuid) {
        notificationProfileVersionRepository.detachHistoricalInstanceReferences(notificationInstanceRefUuid);
    }

    @Transactional
    public int detachNotificationInstanceRefUuid(UUID notificationInstanceRefUuid) {
        return notificationProfileVersionRepository.detachNotificationInstanceRefUuid(notificationInstanceRefUuid);
    }
}
