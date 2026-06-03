package com.czertainly.core.signing.record;

import com.czertainly.core.dao.entity.signing.SigningRecord;
import com.czertainly.core.dao.entity.signing.SigningRecordOutbox;
import com.czertainly.core.model.signing.SigningProfileModel;
import com.czertainly.core.model.signing.SigningRecordPolicyModel;
import org.junit.jupiter.api.Test;

import java.time.Instant;
import java.util.UUID;

import static com.czertainly.core.model.signing.SigningProfileModelBuilder.aSigningProfile;
import static com.czertainly.core.model.signing.SigningRecordPolicyModelBuilder.*;
import static com.czertainly.core.signing.record.SigningRecordInputBuilder.aSigningRecordInput;
import static org.junit.jupiter.api.Assertions.*;

class SigningRecordMapperTest {

    private final SigningRecordMapper mapper = new SigningRecordMapper();

    @Test
    void toRecord_copiesScalarFields() {
        // given
        var profileUuid = UUID.fromString("11111111-1111-1111-1111-111111111111");
        var signingTime = Instant.parse("2026-03-01T12:00:00Z");
        var profileVersion = 7;
        var displayName = "my-record";
        SigningProfileModel<?, ?> profile = aSigningProfile().uuid(profileUuid).version(profileVersion).build();
        SigningRecordInput input = aSigningRecordInput()
                .signingProfile(profile)
                .signingTime(signingTime)
                .displayName(displayName)
                .build();

        // when
        SigningRecord record = mapper.toRecord(input);

        // then
        assertEquals(displayName, record.getName());
        assertEquals(profileUuid, record.getSigningProfileUuid());
        assertEquals(profileVersion, record.getSigningProfileVersion());
        assertEquals(signingTime, record.getSigningTime());
    }

    @Test
    void toRecord_generatesUuid() {
        // given
        SigningRecordInput input = aSigningRecordInput().build();

        // when
        SigningRecord record = mapper.toRecord(input);

        // then
        assertNotNull(record.getUuid());
    }

    @Test
    void toRecord_recordsAllContent_whenPolicyRecordsEverything() {
        // given
        SigningRecordInput input = inputWithPolicy(recordingEverything().build());

        // when
        SigningRecord record = mapper.toRecord(input);

        // then
        assertEquals(input.getRequestMetadataJson(), record.getRequestMetadataJson());
        assertArrayEquals(input.getSignature(), record.getSignatureValue());
        assertArrayEquals(input.getSignedDocument(), record.getSignedDocument());
        assertArrayEquals(input.getDtbs(), record.getDtbs());
    }

    @Test
    void toRecord_recordsNoContent_whenPolicyRecordsNothing() {
        // given
        SigningRecordInput input = inputWithPolicy(notRecording().build());

        // when
        SigningRecord record = mapper.toRecord(input);

        // then
        assertNull(record.getRequestMetadataJson());
        assertNull(record.getSignatureValue());
        assertNull(record.getSignedDocument());
        assertNull(record.getDtbs());
    }

    @Test
    void toRecord_recordsOnlyRequestMetadata_whenOnlyThatToggleEnabled() {
        // given
        SigningRecordPolicyModel onlyRequestMetadata = aSigningRecordPolicy().recordRequestMetadata(true).build();
        SigningRecordInput input = inputWithPolicy(onlyRequestMetadata);

        // when
        SigningRecord record = mapper.toRecord(input);

        // then
        assertEquals(input.getRequestMetadataJson(), record.getRequestMetadataJson());
        assertNull(record.getSignatureValue());
        assertNull(record.getSignedDocument());
        assertNull(record.getDtbs());
    }

    @Test
    void toRecord_recordsOnlySignature_whenOnlyThatToggleEnabled() {
        // given
        SigningRecordPolicyModel onlySignature = aSigningRecordPolicy().recordSignature(true).build();
        SigningRecordInput input = inputWithPolicy(onlySignature);

        // when
        SigningRecord record = mapper.toRecord(input);

        // then
        assertArrayEquals(input.getSignature(), record.getSignatureValue());
        assertNull(record.getRequestMetadataJson());
        assertNull(record.getSignedDocument());
        assertNull(record.getDtbs());
    }

    @Test
    void toRecord_recordsOnlySignedDocument_whenOnlyThatToggleEnabled() {
        // given
        SigningRecordPolicyModel onlySignedDocument = aSigningRecordPolicy().recordSignedDocument(true).build();
        SigningRecordInput input = inputWithPolicy(onlySignedDocument);

        // when
        SigningRecord record = mapper.toRecord(input);

        // then
        assertArrayEquals(input.getSignedDocument(), record.getSignedDocument());
        assertNull(record.getRequestMetadataJson());
        assertNull(record.getSignatureValue());
        assertNull(record.getDtbs());
    }

    @Test
    void toRecord_recordsOnlyDtbs_whenOnlyThatToggleEnabled() {
        // given
        SigningRecordPolicyModel onlyDtbs = aSigningRecordPolicy().recordDtbs(true).build();
        SigningRecordInput input = inputWithPolicy(onlyDtbs);

        // when
        SigningRecord record = mapper.toRecord(input);

        // then
        assertArrayEquals(input.getDtbs(), record.getDtbs());
        assertNull(record.getRequestMetadataJson());
        assertNull(record.getSignatureValue());
        assertNull(record.getSignedDocument());
    }

    @Test
    void toOutbox_copiesScalarFields() {
        // given
        var profileUuid = UUID.fromString("11111111-1111-1111-1111-111111111111");
        var profileVersion = 7;
        var signingTime = Instant.parse("2026-03-01T12:00:00Z");
        var displayName = "my-record";
        SigningProfileModel<?, ?> profile = aSigningProfile()
                .uuid(profileUuid)
                .version(profileVersion)
                .build();
        SigningRecordInput input = aSigningRecordInput()
                .signingProfile(profile)
                .signingTime(signingTime)
                .displayName(displayName)
                .build();

        // when
        SigningRecordOutbox outbox = mapper.toOutbox(input);

        // then
        assertNotNull(outbox.getUuid());
        assertEquals(displayName, outbox.getName());
        assertEquals(profileUuid, outbox.getSigningProfileUuid());
        assertEquals(profileVersion, outbox.getSigningProfileVersion());
        assertEquals(signingTime, outbox.getSigningTime());
    }

    @Test
    void toOutbox_recordsAllContent_whenPolicyRecordsEverything() {
        // given
        SigningRecordInput input = inputWithPolicy(recordingEverything().build());

        // when
        SigningRecordOutbox outbox = mapper.toOutbox(input);

        // then
        assertEquals(input.getRequestMetadataJson(), outbox.getRequestMetadataJson());
        assertArrayEquals(input.getSignature(), outbox.getSignatureValue());
        assertArrayEquals(input.getSignedDocument(), outbox.getSignedDocument());
        assertArrayEquals(input.getDtbs(), outbox.getDtbs());
    }

    @Test
    void toOutbox_recordsNoContent_whenPolicyRecordsNothing() {
        // given
        SigningRecordInput input = inputWithPolicy(notRecording().build());

        // when
        SigningRecordOutbox outbox = mapper.toOutbox(input);

        // then
        assertNull(outbox.getRequestMetadataJson());
        assertNull(outbox.getSignatureValue());
        assertNull(outbox.getSignedDocument());
        assertNull(outbox.getDtbs());
    }

    @Test
    void toOutbox_recordsOnlyRequestMetadata_whenOnlyThatToggleEnabled() {
        // given
        SigningRecordPolicyModel onlyRequestMetadata = aSigningRecordPolicy().recordRequestMetadata(true).build();
        SigningRecordInput input = inputWithPolicy(onlyRequestMetadata);

        // when
        SigningRecordOutbox outbox = mapper.toOutbox(input);

        // then
        assertEquals(input.getRequestMetadataJson(), outbox.getRequestMetadataJson());
        assertNull(outbox.getSignatureValue());
        assertNull(outbox.getSignedDocument());
        assertNull(outbox.getDtbs());
    }

    @Test
    void toOutbox_recordsOnlySignature_whenOnlyThatToggleEnabled() {
        // given
        SigningRecordPolicyModel onlySignature = aSigningRecordPolicy().recordSignature(true).build();
        SigningRecordInput input = inputWithPolicy(onlySignature);

        // when
        SigningRecordOutbox outbox = mapper.toOutbox(input);

        // then
        assertArrayEquals(input.getSignature(), outbox.getSignatureValue());
        assertNull(outbox.getRequestMetadataJson());
        assertNull(outbox.getSignedDocument());
        assertNull(outbox.getDtbs());
    }

    @Test
    void toOutbox_recordsOnlySignedDocument_whenOnlyThatToggleEnabled() {
        // given
        SigningRecordPolicyModel onlySignedDocument = aSigningRecordPolicy().recordSignedDocument(true).build();
        SigningRecordInput input = inputWithPolicy(onlySignedDocument);

        // when
        SigningRecordOutbox outbox = mapper.toOutbox(input);

        // then
        assertArrayEquals(input.getSignedDocument(), outbox.getSignedDocument());
        assertNull(outbox.getRequestMetadataJson());
        assertNull(outbox.getSignatureValue());
        assertNull(outbox.getDtbs());
    }

    @Test
    void toOutbox_recordsOnlyDtbs_whenOnlyThatToggleEnabled() {
        // given
        SigningRecordPolicyModel onlyDtbs = aSigningRecordPolicy().recordDtbs(true).build();
        SigningRecordInput input = inputWithPolicy(onlyDtbs);

        // when
        SigningRecordOutbox outbox = mapper.toOutbox(input);

        // then
        assertArrayEquals(input.getDtbs(), outbox.getDtbs());
        assertNull(outbox.getRequestMetadataJson());
        assertNull(outbox.getSignatureValue());
        assertNull(outbox.getSignedDocument());
    }

    private SigningRecordInput inputWithPolicy(SigningRecordPolicyModel policy) {
        return aSigningRecordInput()
                .signingProfile(aSigningProfile().recordPolicy(policy).build())
                .build();
    }
}
