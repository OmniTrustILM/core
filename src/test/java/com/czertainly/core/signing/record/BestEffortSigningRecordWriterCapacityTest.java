package com.czertainly.core.signing.record;

import com.czertainly.api.model.client.signing.profile.scheme.SigningScheme;
import com.czertainly.api.model.client.signing.profile.workflow.SigningWorkflowType;
import com.czertainly.core.dao.entity.signing.SigningProfile;
import com.czertainly.core.dao.entity.signing.SigningProfileVersion;
import com.czertainly.core.dao.repository.signing.SigningProfileRepository;
import com.czertainly.core.dao.repository.signing.SigningProfileVersionRepository;
import com.czertainly.core.signing.record.BestEffortSigningRecordWriter;
import com.czertainly.core.signing.record.SigningRecordInput;
import com.czertainly.core.util.BaseSpringBootTest;
import io.micrometer.core.instrument.MeterRegistry;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.test.context.TestPropertySource;

import java.time.OffsetDateTime;

import static org.junit.jupiter.api.Assertions.assertTrue;

@TestPropertySource(properties = {
        "signing-record.best-effort.queue-capacity=10",
        "signing-record.best-effort.flush-interval-ms=600000"
})
class BestEffortSigningRecordWriterCapacityTest extends BaseSpringBootTest {

    @Autowired private BestEffortSigningRecordWriter writer;
    @Autowired private SigningProfileRepository profileRepo;
    @Autowired private SigningProfileVersionRepository versionRepo;
    @Autowired private MeterRegistry registry;

    @Test
    void dropOldestIncrementsCounterPastCapacity() {
        SigningProfile p = new SigningProfile();
        p.setName("be-cap-" + System.nanoTime());
        p.setSigningScheme(SigningScheme.MANAGED);
        p.setWorkflowType(SigningWorkflowType.CONTENT_SIGNING);
        p.setLatestVersion(1);
        p = profileRepo.saveAndFlush(p);
        SigningProfileVersion v = new SigningProfileVersion();
        v.setSigningProfile(p); v.setVersion(1);
        v.setSigningScheme(SigningScheme.MANAGED); v.setWorkflowType(SigningWorkflowType.CONTENT_SIGNING);
        v.setRecordSignature(true);
        v = versionRepo.saveAndFlush(v);

        for (int i = 0; i < 100; i++) {
            writer.record(SigningRecordInput.builder()
                    .profile(p).version(v)
                    .signingTime(OffsetDateTime.now())
                    .signature(new byte[]{(byte) i})
                    .build());
        }

        double dropped = registry.get("signing_record.best_effort.dropped.total")
                .tag("reason", "queue_full").counter().count();
        assertTrue(dropped > 0, "expected drop counter to be incremented");
    }
}
