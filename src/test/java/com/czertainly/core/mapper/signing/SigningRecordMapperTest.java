package com.czertainly.core.mapper.signing;

import com.czertainly.core.dao.entity.signing.SigningRecord;
import com.czertainly.core.dao.entity.signing.SigningRecordOutbox;
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
        outbox.setRequestMetadataJson("{ \"alg\": \"ES256\" }");
        outbox.setSignatureValue("the-signature".getBytes());
        outbox.setSignedDocument("the-signed-document".getBytes());
        outbox.setDtbs("the-data-to-be-signed".getBytes());

        // when
        SigningRecord record = SigningRecordMapper.toRecord(outbox);

        // then the record mirrors the row, keeping the row's own UUID (no new one is generated)
        assertEquals(outbox.getUuid(), record.getUuid());
        assertEquals(outbox.getName(), record.getName());
        assertEquals(outbox.getSigningProfileUuid(), record.getSigningProfileUuid());
        assertEquals(outbox.getSigningProfileVersion(), record.getSigningProfileVersion());
        assertEquals(outbox.getSigningTime(), record.getSigningTime());
        assertEquals(outbox.getRequestMetadataJson(), record.getRequestMetadataJson());
        assertArrayEquals(outbox.getSignatureValue(), record.getSignatureValue());
        assertArrayEquals(outbox.getSignedDocument(), record.getSignedDocument());
        assertArrayEquals(outbox.getDtbs(), record.getDtbs());
    }

    @Test
    void toRecordFromOutbox_appliesNoPolicyGating_copyingNullContentAsIs() {
        // given a row staged with no recordable content (the policy gating already happened at staging time)
        var outbox = new SigningRecordOutbox();
        outbox.setUuid(UUID.fromString("33333333-3333-3333-3333-333333333333"));
        outbox.setSigningProfileVersion(1);

        // when
        SigningRecord record = SigningRecordMapper.toRecord(outbox);

        // then the absent content is carried over untouched, not re-evaluated against any policy
        assertEquals(outbox.getUuid(), record.getUuid());
        assertNull(record.getRequestMetadataJson());
        assertNull(record.getSignatureValue());
        assertNull(record.getSignedDocument());
        assertNull(record.getDtbs());
    }
}
