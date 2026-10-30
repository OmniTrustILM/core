package com.otilm.core.integration.service.writer;

import com.otilm.api.model.core.auth.Resource;
import com.otilm.api.model.core.notification.RecipientType;
import com.otilm.api.model.core.other.ResourceEvent;
import com.otilm.core.dao.entity.notifications.NotificationProfile;
import com.otilm.core.dao.entity.notifications.NotificationProfileVersion;
import com.otilm.core.dao.entity.notifications.PendingNotification;
import com.otilm.core.dao.repository.notifications.NotificationProfileRepository;
import com.otilm.core.dao.repository.notifications.NotificationProfileVersionRepository;
import com.otilm.core.dao.repository.notifications.PendingNotificationRepository;
import com.otilm.core.service.writer.PendingNotificationWriter;
import com.otilm.core.util.BaseSpringBootTest;
import java.util.List;
import java.util.UUID;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicReference;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.context.SecurityContextHolder;

/**
 * Proves the suppression-row upsert is atomic: two consumers recording a send for the same (profile, resource, object,
 * event) at the same time must converge on one row with an accurate repetition count, and the pinned profile version
 * must never change on conflict. The pre-upsert read-then-insert flow produced duplicate rows in exactly this race.
 */
class PendingNotificationConcurrentUpsertITest extends BaseSpringBootTest {

    private static final Resource RESOURCE = Resource.CERTIFICATE;
    private static final ResourceEvent EVENT = ResourceEvent.CERTIFICATE_EXPIRING;

    @Autowired
    private PendingNotificationWriter pendingNotificationWriter;
    @Autowired
    private PendingNotificationRepository pendingNotificationRepository;
    @Autowired
    private NotificationProfileRepository notificationProfileRepository;
    @Autowired
    private NotificationProfileVersionRepository notificationProfileVersionRepository;

    private UUID profileUuid;
    private UUID objectUuid;

    @BeforeEach
    void seedProfile() {
        NotificationProfile profile = new NotificationProfile();
        profile.setName("concurrent-upsert-profile");
        profile = notificationProfileRepository.save(profile);
        profileUuid = profile.getUuid();

        NotificationProfileVersion version = new NotificationProfileVersion();
        version.setNotificationProfileUuid(profileUuid);
        version.setVersion(1);
        version.setRecipientType(RecipientType.NONE);
        version.setInternalNotification(false);
        version.setRepetitions(10);
        notificationProfileVersionRepository.save(version);

        objectUuid = UUID.randomUUID();
    }

    @Test
    void concurrentRecordSentConvergesOnOneRow() throws Exception {
        int workers = 2;
        CountDownLatch ready = new CountDownLatch(workers);
        CountDownLatch fire = new CountDownLatch(1);
        ExecutorService pool = Executors.newFixedThreadPool(workers);
        AtomicReference<Throwable> failure = new AtomicReference<>();

        try {
            List<Future<?>> futures = List
                    .of(pool.submit(raceWorker(ready, fire, failure)), pool.submit(raceWorker(ready, fire, failure)));

            Assertions.assertTrue(ready.await(10, TimeUnit.SECONDS), "workers did not become ready in time");
            fire.countDown();
            for (Future<?> future : futures) {
                future.get(20, TimeUnit.SECONDS);
            }
        } finally {
            pool.shutdownNow();
        }

        Assertions.assertNull(failure.get(), () -> "worker failed: " + failure.get());

        PendingNotification row = pendingNotificationRepository
                .findByNotificationProfileUuidAndResourceAndObjectUuidAndEvent(profileUuid, RESOURCE, objectUuid,
                        EVENT);
        Assertions
                .assertNotNull(row,
                        "exactly one suppression row should exist; a duplicate would make the finder throw");
        Assertions.assertEquals(2, row.getRepetitions(), "both concurrent sends must be counted");
        Assertions.assertEquals(1, row.getVersion());
        Assertions.assertNotNull(row.getLastSentAt());

        // A later send updates in place and never touches the pinned version.
        pendingNotificationWriter.recordSent(profileUuid, RESOURCE, objectUuid, EVENT, 7);
        PendingNotification updated = pendingNotificationRepository
                .findByNotificationProfileUuidAndResourceAndObjectUuidAndEvent(profileUuid, RESOURCE, objectUuid,
                        EVENT);
        Assertions.assertEquals(3, updated.getRepetitions());
        Assertions.assertEquals(1, updated.getVersion(), "the pinned version must survive conflicts");
    }

    private Runnable raceWorker(CountDownLatch ready, CountDownLatch fire, AtomicReference<Throwable> failure) {
        // The security context does not propagate to pool threads; each worker re-injects it.
        var authentication = SecurityContextHolder.getContext().getAuthentication();
        return () -> {
            SecurityContextHolder.getContext().setAuthentication(authentication);
            try {
                ready.countDown();
                fire.await(10, TimeUnit.SECONDS);
                pendingNotificationWriter.recordSent(profileUuid, RESOURCE, objectUuid, EVENT, 1);
            } catch (Throwable t) {
                failure.compareAndSet(null, t);
            } finally {
                SecurityContextHolder.clearContext();
            }
        };
    }
}
