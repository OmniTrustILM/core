package com.czertainly.core.signing.record;

import com.czertainly.api.model.client.signing.profile.scheme.SigningScheme;
import com.czertainly.api.model.client.signing.profile.workflow.SigningWorkflowType;
import com.czertainly.core.dao.entity.signing.SigningProfile;
import com.czertainly.core.dao.entity.signing.SigningRecord;
import com.czertainly.core.dao.entity.signing.SigningRecordOutbox;
import com.czertainly.core.dao.repository.signing.SigningProfileRepository;
import com.czertainly.core.dao.repository.signing.SigningRecordOutboxRepository;
import com.czertainly.core.dao.repository.signing.SigningRecordRepository;
import com.czertainly.core.service.SchedulerService;
import com.czertainly.core.signing.record.SigningRecordOutboxDrainer;
import com.czertainly.core.util.BaseSpringBootTest;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.context.bean.override.mockito.MockitoBean;

import java.time.OffsetDateTime;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

@TestPropertySource(properties = "scheduled-tasks.enabled=true")
class SigningRecordOutboxDrainerTest extends BaseSpringBootTest {

    @MockitoBean
    @SuppressWarnings("unused")
    private SchedulerService schedulerService;

    @Autowired
    private SigningRecordOutboxDrainer drainer;
    @Autowired
    private SigningProfileRepository profileRepo;
    @Autowired
    private SigningRecordOutboxRepository outboxRepo;
    @Autowired
    private SigningRecordRepository recordRepo;

    private SigningProfile seedProfile() {
        SigningProfile p = new SigningProfile();
        p.setName("dp-" + System.nanoTime());
        p.setSigningScheme(SigningScheme.MANAGED);
        p.setWorkflowType(SigningWorkflowType.CONTENT_SIGNING);
        p.setLatestVersion(1);
        return profileRepo.saveAndFlush(p);
    }

    private SigningRecordOutbox seedOutbox(UUID profileUuid) {
        SigningRecordOutbox row = new SigningRecordOutbox();
        row.setUuid(UUID.randomUUID());
        row.setSigningProfileUuid(profileUuid);
        row.setSigningProfileVersion(1);
        row.setSigningTime(OffsetDateTime.now());
        row.setSignatureValue(new byte[]{7});
        return outboxRepo.saveAndFlush(row);
    }

    @Test
    void movesRowsFromOutboxToSigningRecord() {
        UUID pUuid = seedProfile().getUuid();
        for (int i = 0; i < 3; i++)
            seedOutbox(pUuid);

        drainer.drainOnce();

        assertEquals(0, outboxRepo.count());
        assertEquals(3, recordRepo.count());
    }

    @Test
    void crashRecoveryIsIdempotent() {
        UUID pUuid = seedProfile().getUuid();
        SigningRecordOutbox row = seedOutbox(pUuid);

        SigningRecord pre = new SigningRecord();
        pre.setUuid(row.getUuid());
        pre.setSigningProfileUuid(pUuid);
        pre.setSigningProfileVersion(1);
        pre.setSigningTime(row.getSigningTime());
        recordRepo.saveAndFlush(pre);

        drainer.drainOnce();

        assertEquals(0, outboxRepo.count());
        assertEquals(1, recordRepo.count());
    }

    @Test
    void poisonRowSkippedAndCounted() {
        UUID pUuid = seedProfile().getUuid();
        SigningRecordOutbox row = seedOutbox(pUuid);
        row.setAttempts(99);
        outboxRepo.saveAndFlush(row);

        drainer.drainOnce();

        assertTrue(outboxRepo.findById(row.getUuid()).isPresent());
        assertEquals(0, recordRepo.count());
    }
}
