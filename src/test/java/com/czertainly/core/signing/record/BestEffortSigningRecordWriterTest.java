package com.czertainly.core.signing.record;

import com.czertainly.api.model.client.signing.profile.scheme.SigningScheme;
import com.czertainly.api.model.client.signing.profile.workflow.SigningWorkflowType;
import com.czertainly.core.dao.entity.signing.SigningProfile;
import com.czertainly.core.dao.entity.signing.SigningProfileVersion;
import com.czertainly.core.dao.repository.signing.SigningProfileRepository;
import com.czertainly.core.dao.repository.signing.SigningProfileVersionRepository;
import com.czertainly.core.dao.repository.signing.SigningRecordRepository;
import com.czertainly.core.signing.record.BestEffortSigningRecordWriter;
import com.czertainly.core.signing.record.SigningRecordInput;
import com.czertainly.core.util.BaseSpringBootTest;
import org.awaitility.Awaitility;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;

import java.time.Duration;
import java.time.OffsetDateTime;

import static org.junit.jupiter.api.Assertions.assertEquals;

class BestEffortSigningRecordWriterTest extends BaseSpringBootTest {

    @Autowired private BestEffortSigningRecordWriter writer;
    @Autowired private SigningProfileRepository profileRepo;
    @Autowired private SigningProfileVersionRepository versionRepo;
    @Autowired private SigningRecordRepository recordRepo;

    @Test
    void recordsEventuallyAppearInSigningRecord() {
        SigningProfile p = new SigningProfile();
        p.setName("be-" + System.nanoTime());
        p.setSigningScheme(SigningScheme.MANAGED);
        p.setWorkflowType(SigningWorkflowType.CONTENT_SIGNING);
        p.setLatestVersion(1);
        p = profileRepo.saveAndFlush(p);
        SigningProfileVersion v = new SigningProfileVersion();
        v.setSigningProfile(p); v.setVersion(1);
        v.setSigningScheme(SigningScheme.MANAGED); v.setWorkflowType(SigningWorkflowType.CONTENT_SIGNING);
        v.setRecordSignature(true);
        v = versionRepo.saveAndFlush(v);

        SigningRecordInput in = SigningRecordInput.builder()
                .profile(p).version(v)
                .signingTime(OffsetDateTime.now())
                .signature(new byte[]{42})
                .build();
        writer.record(in);

        Awaitility.await().atMost(Duration.ofSeconds(5))
                .until(() -> recordRepo.count() == 1);
        assertEquals(1, recordRepo.count());
    }
}
