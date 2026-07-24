package com.otilm.core.service.impl;

import com.otilm.api.exception.ValidationException;
import com.otilm.api.model.client.notification.NotificationProfileUpdateRequestDto;
import com.otilm.api.model.core.notification.RecipientType;
import com.otilm.core.dao.entity.notifications.NotificationProfile;
import com.otilm.core.dao.entity.notifications.NotificationProfileVersion;
import com.otilm.core.dao.repository.notifications.NotificationProfileRepository;
import com.otilm.core.dao.repository.notifications.NotificationProfileVersionRepository;
import com.otilm.core.security.authz.SecuredUUID;
import org.hibernate.exception.ConstraintViolationException;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.dao.DataIntegrityViolationException;

import java.sql.SQLException;
import java.util.List;
import java.util.Optional;
import java.util.UUID;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.when;

/**
 * Unit-level coverage for the constraint-violation mapping in {@code persistEditedVersion}: the row lock
 * makes the duplicate-version path unreachable through the service in integration tests, so the mapping
 * is exercised here with synthesized exceptions.
 */
@ExtendWith(MockitoExtension.class)
class NotificationProfileServiceImplPersistEditTest {

    @Mock
    private NotificationProfileRepository notificationProfileRepository;

    @Mock
    private NotificationProfileVersionRepository notificationProfileVersionRepository;

    private NotificationProfileServiceImpl service;

    private SecuredUUID profileUuid;
    private NotificationProfileUpdateRequestDto updateRequest;

    @BeforeEach
    void setUp() {
        service = new NotificationProfileServiceImpl();
        service.setNotificationProfileRepository(notificationProfileRepository);
        service.setNotificationProfileVersionRepository(notificationProfileVersionRepository);

        profileUuid = SecuredUUID.fromUUID(UUID.randomUUID());

        NotificationProfile profile = new NotificationProfile();
        profile.uuid = profileUuid.getValue();
        profile.setName("TestProfile");

        NotificationProfileVersion currentVersion = new NotificationProfileVersion();
        currentVersion.setVersion(1);
        currentVersion.setRecipientType(RecipientType.OWNER);
        currentVersion.setInternalNotification(true);

        updateRequest = new NotificationProfileUpdateRequestDto();
        updateRequest.setRecipientType(RecipientType.OWNER);
        updateRequest.setInternalNotification(true);
        updateRequest.setRepetitions(5);

        when(notificationProfileRepository.findAndLockByUuid(profileUuid.getValue())).thenReturn(Optional.of(profile));
        when(notificationProfileVersionRepository.findTopByNotificationProfileUuidOrderByVersionDesc(profileUuid.getValue())).thenReturn(Optional.of(currentVersion));
    }

    @Test
    void duplicateVersionConstraintViolationIsReportedAsConcurrentModification() {
        when(notificationProfileVersionRepository.saveAndFlush(any()))
                .thenThrow(integrityViolation(NotificationProfileVersion.UNIQUE_VERSION_CONSTRAINT));

        ValidationException e = Assertions.assertThrows(ValidationException.class,
                () -> service.persistEditedVersion(profileUuid, updateRequest, List.of()));
        Assertions.assertTrue(e.getMessage().contains("concurrently modified"),
                "Message should tell the client to retry, but was: " + e.getMessage());
    }

    @Test
    void otherIntegrityViolationsAreRethrownUnchanged() {
        DataIntegrityViolationException foreignKeyViolation = integrityViolation("fk_notification_profile_version_instance");
        when(notificationProfileVersionRepository.saveAndFlush(any())).thenThrow(foreignKeyViolation);

        DataIntegrityViolationException e = Assertions.assertThrows(DataIntegrityViolationException.class,
                () -> service.persistEditedVersion(profileUuid, updateRequest, List.of()));
        Assertions.assertSame(foreignKeyViolation, e, "Non-duplicate integrity violations must surface unchanged");
    }

    @Test
    void integrityViolationWithoutConstraintNameIsRethrownUnchanged() {
        DataIntegrityViolationException anonymousViolation = integrityViolation(null);
        when(notificationProfileVersionRepository.saveAndFlush(any())).thenThrow(anonymousViolation);

        DataIntegrityViolationException e = Assertions.assertThrows(DataIntegrityViolationException.class,
                () -> service.persistEditedVersion(profileUuid, updateRequest, List.of()));
        Assertions.assertSame(anonymousViolation, e);
    }

    private static DataIntegrityViolationException integrityViolation(String constraintName) {
        return new DataIntegrityViolationException("could not execute statement",
                new ConstraintViolationException("could not execute statement", new SQLException("duplicate key"), constraintName));
    }
}
