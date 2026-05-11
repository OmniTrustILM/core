package com.czertainly.core.signing.record;

import com.czertainly.api.model.client.signing.profile.record.SigningRecordPersistenceMode;
import com.czertainly.api.model.client.signing.profile.scheme.SigningScheme;
import com.czertainly.api.model.client.signing.profile.workflow.SigningWorkflowType;
import com.czertainly.core.dao.entity.signing.SigningProfile;
import com.czertainly.core.dao.entity.signing.SigningProfileVersion;
import com.czertainly.core.dao.repository.signing.SigningProfileRepository;
import com.czertainly.core.dao.repository.signing.SigningProfileVersionRepository;
import com.czertainly.core.dao.repository.signing.SigningRecordOutboxRepository;
import com.czertainly.core.dao.repository.signing.SigningRecordRepository;
import com.czertainly.core.service.SchedulerService;
import com.czertainly.core.signing.record.SigningRecordInput;
import com.czertainly.core.signing.record.SigningRecordOutboxDrainer;
import com.czertainly.core.signing.record.SigningRecordWriter;
import com.czertainly.core.signing.record.SigningRecordWriterFactory;
import com.czertainly.core.util.BaseSpringBootTest;
import io.micrometer.core.instrument.MeterRegistry;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.context.bean.override.mockito.MockitoBean;

import java.time.OffsetDateTime;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

@TestPropertySource(properties = "scheduled-tasks.enabled=true")
class SigningRecordEndToEndTest extends BaseSpringBootTest {

    @MockitoBean
    @SuppressWarnings("unused")
    private SchedulerService schedulerService;

    @Autowired
    private SigningRecordWriterFactory factory;
    @Autowired
    private SigningRecordOutboxDrainer drainer;
    @Autowired
    private SigningProfileRepository profileRepo;
    @Autowired
    private SigningProfileVersionRepository versionRepo;
    @Autowired
    private SigningRecordOutboxRepository outboxRepo;
    @Autowired
    private SigningRecordRepository recordRepo;
    @Autowired
    private MeterRegistry registry;

    @Test
    void deferredDurableEndToEnd() {
        SigningProfile p = new SigningProfile();
        p.setName("e2e-" + System.nanoTime());
        p.setSigningScheme(SigningScheme.MANAGED);
        p.setWorkflowType(SigningWorkflowType.CONTENT_SIGNING);
        p.setLatestVersion(1);
        p.setPersistenceMode(SigningRecordPersistenceMode.DEFERRED_DURABLE);
        p = profileRepo.saveAndFlush(p);

        SigningProfileVersion v = new SigningProfileVersion();
        v.setSigningProfile(p);
        v.setVersion(1);
        v.setSigningScheme(SigningScheme.MANAGED);
        v.setWorkflowType(SigningWorkflowType.CONTENT_SIGNING);
        v.setRecordSignature(true);
        v.setRecordRequestMetadata(true);
        v = versionRepo.saveAndFlush(v);

        SigningRecordWriter w = factory.writerFor(p);
        w.record(SigningRecordInput.builder()
                .profile(p).version(v)
                .signingTime(OffsetDateTime.now())
                .signature(new byte[]{1, 2, 3})
                .requestMetadataJson("{\"alg\":\"X\"}")
                .build());

        assertEquals(1, outboxRepo.count());
        drainer.drainOnce();
        assertEquals(0, outboxRepo.count());
        assertEquals(1, recordRepo.count());

        assertTrue(registry.get("signing_record.created.total").tag("mode", "DEFERRED_DURABLE")
                .counter().count() >= 1);
        assertTrue(registry.get("signing_record.outbox.drained.total").counter().count() >= 1);
    }
}
