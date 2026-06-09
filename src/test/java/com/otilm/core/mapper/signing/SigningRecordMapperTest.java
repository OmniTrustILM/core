package com.otilm.core.mapper.signing;

import com.otilm.core.dao.entity.signing.SigningRecord;
import com.otilm.core.dao.entity.signing.SigningRecordOutbox;
import org.junit.jupiter.api.Test;

import java.time.Instant;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;

class SigningRecordMapperTest {

    @Test
    void toRecordFromOutbox_copiesEveryFieldVerbatimUnderTheSameUuid() {
        // given a staged outbox row with every field populated
        var outbox = new SigningRecordOutbox();
        outbox.setUuid(UUID.fromString("22222222-2222-2222-2222-222222222222"));
        outbox.setName("staged-record");
        outbox.setSigningProfileUuid(UUID.fromString("11111111-1111-1111-1111-111111111111"));
        outbox.setSigningProfileVersion(7);
        outbox.setSigningTime(Instant.parse("2026-03-01T12:00:00Z"));
        outbox.setRequestedByUuid(UUID.fromString("99999999-9999-9999-9999-999999999999"));
        outbox.setRequestedByUsername("alice");
        outbox.setRequestMetadataJson("{ \"alg\": \"ES256\" }");
        outbox.setSignatureValue("the-signature".getBytes());
        outbox.setSignedDocument("the-signed-document".getBytes());
        outbox.setDtbs("the-data-to-be-signed".getBytes());

        // when
        SigningRecord signingRecord = SigningRecordMapper.toRecord(outbox);

        // then the record mirrors the row, keeping the row's own UUID (no new one is generated)
        assertEquals(outbox.getUuid(), signingRecord.getUuid());
        assertEquals(outbox.getName(), signingRecord.getName());
        assertEquals(outbox.getSigningProfileUuid(), signingRecord.getSigningProfileUuid());
        assertEquals(outbox.getSigningProfileVersion(), signingRecord.getSigningProfileVersion());
        assertEquals(outbox.getSigningTime(), signingRecord.getSigningTime());
        assertEquals(outbox.getRequestedByUuid(), signingRecord.getRequestedByUuid());
        assertEquals(outbox.getRequestedByUsername(), signingRecord.getRequestedByUsername());
        assertEquals(outbox.getRequestMetadataJson(), signingRecord.getRequestMetadataJson());
        assertArrayEquals(outbox.getSignatureValue(), signingRecord.getSignatureValue());
        assertArrayEquals(outbox.getSignedDocument(), signingRecord.getSignedDocument());
        assertArrayEquals(outbox.getDtbs(), signingRecord.getDtbs());
    }

    @Test
    void toRecordFromOutbox_appliesNoPolicyGating_copyingNullContentAsIs() {
        // given a row staged with no recordable content (the policy gating already happened at staging time)
        var outbox = new SigningRecordOutbox();
        outbox.setUuid(UUID.fromString("33333333-3333-3333-3333-333333333333"));
        outbox.setSigningProfileVersion(1);

        // when
        SigningRecord signingRecord = SigningRecordMapper.toRecord(outbox);

        // then the absent content is carried over untouched, not re-evaluated against any policy
        assertEquals(outbox.getUuid(), signingRecord.getUuid());
        assertNull(signingRecord.getRequestMetadataJson());
        assertNull(signingRecord.getSignatureValue());
        assertNull(signingRecord.getSignedDocument());
        assertNull(signingRecord.getDtbs());
    }
}
