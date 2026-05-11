package com.czertainly.core.signing.record;

import com.czertainly.api.model.client.signing.profile.scheme.SigningScheme;
import com.czertainly.api.model.client.signing.profile.workflow.SigningWorkflowType;
import com.czertainly.core.dao.entity.signing.SigningProfile;
import com.czertainly.core.dao.entity.signing.SigningProfileVersion;
import com.czertainly.core.dao.entity.signing.SigningRecord;
import com.czertainly.core.dao.repository.signing.SigningProfileRepository;
import com.czertainly.core.dao.repository.signing.SigningProfileVersionRepository;
import com.czertainly.core.dao.repository.signing.SigningRecordRepository;
import com.czertainly.core.signing.record.ImmediateSigningRecordWriter;
import com.czertainly.core.signing.record.SigningRecordInput;
import com.czertainly.core.util.BaseSpringBootTest;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;

import java.time.OffsetDateTime;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;

class ImmediateSigningRecordWriterTest extends BaseSpringBootTest {

    @Autowired private ImmediateSigningRecordWriter writer;
    @Autowired private SigningProfileRepository profileRepo;
    @Autowired private SigningProfileVersionRepository versionRepo;
    @Autowired private SigningRecordRepository recordRepo;

    private SigningRecordInput build(SigningProfile p, SigningProfileVersion v) {
        return SigningRecordInput.builder()
                .profile(p).version(v)
                .signingTime(OffsetDateTime.now())
                .displayName("disp")
                .requestMetadataJson("{\"alg\":\"X\"}")
                .signature(new byte[]{1, 2})
                .signedDocument(new byte[]{3, 4})
                .dtbs(new byte[]{5, 6})
                .build();
    }

    private SigningProfileVersion seedProfileWithToggles(boolean meta, boolean reqMeta,
                                                         boolean sig, boolean signedDoc, boolean dtbs) {
        SigningProfile p = new SigningProfile();
        p.setName("imm-" + System.nanoTime());
        p.setSigningScheme(SigningScheme.MANAGED);
        p.setWorkflowType(SigningWorkflowType.CONTENT_SIGNING);
        p.setLatestVersion(1);
        p = profileRepo.saveAndFlush(p);

        SigningProfileVersion v = new SigningProfileVersion();
        v.setSigningProfile(p);
        v.setVersion(1);
        v.setSigningScheme(SigningScheme.MANAGED);
        v.setWorkflowType(SigningWorkflowType.CONTENT_SIGNING);
        v.setRecordMetadata(meta);
        v.setRecordRequestMetadata(reqMeta);
        v.setRecordSignature(sig);
        v.setRecordSignedDocument(signedDoc);
        v.setRecordDtbs(dtbs);
        return versionRepo.saveAndFlush(v);
    }

    @Test
    void writesPersistsOnlyToggledColumns() {
        SigningProfileVersion v = seedProfileWithToggles(true, true, true, false, true);

        writer.record(build(v.getSigningProfile(), v));

        List<SigningRecord> all = recordRepo.findAll();
        assertEquals(1, all.size());
        SigningRecord r = all.get(0);
        assertNotNull(r.getName());
        assertNotNull(r.getRequestMetadataJson());
        assertArrayEquals(new byte[]{1, 2}, r.getSignatureValue());
        assertNull(r.getSignedDocument()); // toggle off
        assertArrayEquals(new byte[]{5, 6}, r.getDtbs());
    }

    @Test
    void noToggleEnabledIsNoOp() {
        SigningProfileVersion v = seedProfileWithToggles(false, false, false, false, false);

        writer.record(build(v.getSigningProfile(), v));

        assertEquals(0, recordRepo.count());
    }
}
