package com.czertainly.core.signing.record;

import com.czertainly.api.model.client.signing.profile.scheme.SigningScheme;
import com.czertainly.api.model.client.signing.profile.workflow.SigningWorkflowType;
import com.czertainly.core.dao.entity.signing.SigningProfile;
import com.czertainly.core.dao.entity.signing.SigningProfileVersion;
import com.czertainly.core.dao.entity.signing.SigningRecordOutbox;
import com.czertainly.core.dao.repository.signing.SigningProfileRepository;
import com.czertainly.core.dao.repository.signing.SigningProfileVersionRepository;
import com.czertainly.core.dao.repository.signing.SigningRecordOutboxRepository;
import com.czertainly.core.dao.repository.signing.SigningRecordRepository;
import com.czertainly.core.signing.record.OutboxSigningRecordWriter;
import com.czertainly.core.signing.record.SigningRecordInput;
import com.czertainly.core.util.BaseSpringBootTest;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;

import java.time.OffsetDateTime;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;

class OutboxSigningRecordWriterTest extends BaseSpringBootTest {

    @Autowired
    private OutboxSigningRecordWriter writer;
    @Autowired
    private SigningProfileRepository profileRepo;
    @Autowired
    private SigningProfileVersionRepository versionRepo;
    @Autowired
    private SigningRecordOutboxRepository outboxRepo;
    @Autowired
    private SigningRecordRepository recordRepo;

    @Test
    void enqueuesIntoOutboxNotIntoSigningRecord() {
        SigningProfile p = new SigningProfile();
        p.setName("ob");
        p.setSigningScheme(SigningScheme.MANAGED);
        p.setWorkflowType(SigningWorkflowType.CONTENT_SIGNING);
        p.setLatestVersion(1);
        p = profileRepo.saveAndFlush(p);
        SigningProfileVersion v = new SigningProfileVersion();
        v.setSigningProfile(p);
        v.setVersion(1);
        v.setSigningScheme(SigningScheme.MANAGED);
        v.setWorkflowType(SigningWorkflowType.CONTENT_SIGNING);
        v.setRecordSignature(true);
        v.setRecordDtbs(true);
        v = versionRepo.saveAndFlush(v);

        writer.record(SigningRecordInput.builder()
                .profile(p).version(v)
                .signingTime(OffsetDateTime.now())
                .signature(new byte[]{1}).dtbs(new byte[]{2})
                .build());

        List<SigningRecordOutbox> rows = outboxRepo.findAll();
        assertEquals(1, rows.size());
        assertArrayEquals(new byte[]{1}, rows.get(0).getSignatureValue());
        assertArrayEquals(new byte[]{2}, rows.get(0).getDtbs());
        assertEquals(0, recordRepo.count());
    }
}
