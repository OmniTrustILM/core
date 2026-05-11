package com.czertainly.core.signing.record;

import com.czertainly.api.model.client.signing.profile.scheme.SigningScheme;
import com.czertainly.api.model.client.signing.profile.workflow.SigningWorkflowType;
import com.czertainly.core.dao.entity.signing.SigningProfile;
import com.czertainly.core.dao.entity.signing.SigningRecord;
import com.czertainly.core.dao.repository.signing.SigningProfileRepository;
import com.czertainly.core.dao.repository.signing.SigningRecordRepository;
import com.czertainly.core.service.SchedulerService;
import com.czertainly.core.signing.record.SigningRecordRetentionSweeper;
import com.czertainly.core.util.BaseSpringBootTest;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.context.bean.override.mockito.MockitoBean;

import java.time.OffsetDateTime;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.assertEquals;

@TestPropertySource(properties = "scheduled-tasks.enabled=true")
class SigningRecordRetentionSweeperTest extends BaseSpringBootTest {

    @MockitoBean
    @SuppressWarnings("unused")
    private SchedulerService schedulerService;

    @Autowired private SigningRecordRetentionSweeper sweeper;
    @Autowired private SigningProfileRepository profileRepo;
    @Autowired private SigningRecordRepository recordRepo;
    @Autowired private JdbcTemplate jdbc;

    @Test
    void deletesOnlyRecordsOlderThanProfileRetention() {
        SigningProfile p = new SigningProfile();
        p.setName("ret-" + System.nanoTime());
        p.setSigningScheme(SigningScheme.MANAGED);
        p.setWorkflowType(SigningWorkflowType.CONTENT_SIGNING);
        p.setLatestVersion(1);
        p.setRetentionDays(7);
        p = profileRepo.saveAndFlush(p);

        SigningRecord old = new SigningRecord();
        old.setUuid(UUID.randomUUID());
        old.setSigningProfileUuid(p.getUuid());
        old.setSigningProfileVersion(1);
        old.setSigningTime(OffsetDateTime.now().minusDays(10));
        recordRepo.saveAndFlush(old);
        // :TODO:
        jdbc.update("UPDATE core.signing_record SET created_at = ? WHERE uuid = ?",
                OffsetDateTime.now().minusDays(10), old.getUuid());

        SigningRecord fresh = new SigningRecord();
        fresh.setUuid(UUID.randomUUID());
        fresh.setSigningProfileUuid(p.getUuid());
        fresh.setSigningProfileVersion(1);
        fresh.setSigningTime(OffsetDateTime.now());
        recordRepo.saveAndFlush(fresh);

        sweeper.sweep();

        assertEquals(1, recordRepo.count());
        assertEquals(fresh.getUuid(), recordRepo.findAll().get(0).getUuid());
    }

    @Test
    void doesNotDeleteWhenRetentionDaysIsNull() {
        SigningProfile p = new SigningProfile();
        p.setName("ret-null-" + System.nanoTime());
        p.setSigningScheme(SigningScheme.MANAGED);
        p.setWorkflowType(SigningWorkflowType.CONTENT_SIGNING);
        p.setLatestVersion(1);
        p.setRetentionDays(null);
        p = profileRepo.saveAndFlush(p);

        SigningRecord old = new SigningRecord();
        old.setUuid(UUID.randomUUID());
        old.setSigningProfileUuid(p.getUuid());
        old.setSigningProfileVersion(1);
        old.setSigningTime(OffsetDateTime.now().minusDays(365));
        recordRepo.saveAndFlush(old);
        // :TODO:
        jdbc.update("UPDATE core.signing_record SET created_at = ? WHERE uuid = ?",
                OffsetDateTime.now().minusDays(365), old.getUuid());

        sweeper.sweep();

        assertEquals(1, recordRepo.count());
    }

    @Test
    void orphanRecordsAreNotSwept() {
        SigningRecord orphan = new SigningRecord();
        orphan.setUuid(UUID.randomUUID());
        orphan.setSigningProfileUuid(null);
        orphan.setSigningProfileVersion(1);
        orphan.setSigningTime(OffsetDateTime.now().minusDays(365));
        recordRepo.saveAndFlush(orphan);
        // :TODO:
        jdbc.update("UPDATE core.signing_record SET created_at = ? WHERE uuid = ?",
                OffsetDateTime.now().minusDays(365), orphan.getUuid());

        sweeper.sweep();

        assertEquals(1, recordRepo.count());
    }
}
