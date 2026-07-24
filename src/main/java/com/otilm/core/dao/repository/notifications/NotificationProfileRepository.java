package com.otilm.core.dao.repository.notifications;

import com.otilm.core.dao.entity.notifications.NotificationProfile;
import com.otilm.core.dao.repository.SecurityFilterRepository;
import jakarta.persistence.LockModeType;
import org.springframework.data.jpa.repository.EntityGraph;
import org.springframework.data.jpa.repository.Lock;
import org.springframework.stereotype.Repository;

import java.util.Optional;
import java.util.UUID;

@Repository
public interface NotificationProfileRepository extends SecurityFilterRepository<NotificationProfile, UUID> {

    Optional<NotificationProfile> findByName(String name);

    @EntityGraph(attributePaths = {"versions"})
    Optional<NotificationProfile> findWithVersionsByUuid(UUID uuid);

    /**
     * Pessimistic-write variant of {@code findByUuid} for paths that assign the next profile version number.
     * Issues {@code SELECT ... FOR UPDATE} on the profile row so concurrent edits serialize instead of both
     * reading the same latest version and inserting duplicate version numbers. Must be called inside an active
     * transaction, otherwise the lock is released immediately on query completion.
     */
    @Lock(LockModeType.PESSIMISTIC_WRITE)
    Optional<NotificationProfile> findAndLockByUuid(UUID uuid);

}
