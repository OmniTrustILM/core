package com.otilm.core.mapper.signing;

import com.otilm.core.dao.entity.signing.SigningRecord;
import com.otilm.core.dao.entity.signing.SigningRecordOutbox;
import com.otilm.core.model.signing.SigningProfileModel;
import com.otilm.core.model.signing.SigningRecordPolicyModel;
import com.otilm.core.signing.record.SigningRecordInput;
import org.junit.jupiter.api.Test;

import java.time.Instant;
import java.util.UUID;

import static com.otilm.core.util.builders.SigningProfileModelBuilder.aSigningProfile;
import static com.otilm.core.model.signing.SigningRecordPolicyModelBuilder.*;
import static com.otilm.core.signing.record.SigningRecordInputBuilder.aSigningRecordInput;
import static org.junit.jupiter.api.Assertions.*;

class SigningRecordInputMapperTest {

    private final SigningRecordInputMapper mapper = new SigningRecordInputMapper();

    @Test
    void toRecord_copiesScalarFields() {
        // given
        var profileUuid = UUID.fromString("11111111-1111-1111-1111-111111111111");
        var signingTime = Instant.parse("2026-03-01T12:00:00Z");
        var profileVersion = 7;
        var displayName = "my-record";
        SigningProfileModel<?, ?> profile = aSigningProfile().withUuid(profileUuid).withVersion(profileVersion).build();
        SigningRecordInput input = aSigningRecordInput()
                .signingProfile(profile)
                .signingTime(signingTime)
                .displayName(displayName)
                .build();

        // when
        SigningRecord signingRecord = mapper.toRecord(input);

        // then
        assertEquals(displayName, signingRecord.getName());
        assertEquals(profileUuid, signingRecord.getSigningProfileUuid());
        assertEquals(profileVersion, signingRecord.getSigningProfileVersion());
        assertEquals(signingTime, signingRecord.getSigningTime());
        assertEquals(UUID.fromString(input.getRequestedBy().getUuid()), signingRecord.getRequestedByUuid());
        assertEquals(input.getRequestedBy().getName(), signingRecord.getRequestedByUsername());
    }

    @Test
    void toRecord_generatesUuid() {
        // given
        SigningRecordInput input = aSigningRecordInput().build();

        // when
        SigningRecord signingRecord = mapper.toRecord(input);

        // then
        assertNotNull(signingRecord.getUuid());
    }

    @Test
    void toRecord_recordsAllContent_whenPolicyRecordsEverything() {
        // given
        SigningRecordInput input = inputWithPolicy(recordingEverything().build());

        // when
        SigningRecord signingRecord = mapper.toRecord(input);

        // then
        assertEquals(input.getRequestMetadataJson(), signingRecord.getRequestMetadataJson());
        assertArrayEquals(input.getSignature(), signingRecord.getSignatureValue());
        assertArrayEquals(input.getSignedDocument(), signingRecord.getSignedDocument());
        assertArrayEquals(input.getDtbs(), signingRecord.getDtbs());
    }

    @Test
    void toRecord_recordsNoContent_whenPolicyRecordsNothing() {
        // given
        SigningRecordInput input = inputWithPolicy(notRecording().build());

        // when
        SigningRecord signingRecord = mapper.toRecord(input);

        // then the requester identity is captured unconditionally, independent of the content policy
        assertEquals(UUID.fromString(input.getRequestedBy().getUuid()), signingRecord.getRequestedByUuid());
        assertEquals(input.getRequestedBy().getName(), signingRecord.getRequestedByUsername());
        assertNull(signingRecord.getRequestMetadataJson());
        assertNull(signingRecord.getSignatureValue());
        assertNull(signingRecord.getSignedDocument());
        assertNull(signingRecord.getDtbs());
    }

    @Test
    void toRecord_recordsOnlyRequestMetadata_whenOnlyThatToggleEnabled() {
        // given
        SigningRecordPolicyModel onlyRequestMetadata = aSigningRecordPolicy().recordRequestMetadata(true).build();
        SigningRecordInput input = inputWithPolicy(onlyRequestMetadata);

        // when
        SigningRecord signingRecord = mapper.toRecord(input);

        // then
        assertEquals(input.getRequestMetadataJson(), signingRecord.getRequestMetadataJson());
        assertNull(signingRecord.getSignatureValue());
        assertNull(signingRecord.getSignedDocument());
        assertNull(signingRecord.getDtbs());
    }

    @Test
    void toRecord_recordsOnlySignature_whenOnlyThatToggleEnabled() {
        // given
        SigningRecordPolicyModel onlySignature = aSigningRecordPolicy().recordSignature(true).build();
        SigningRecordInput input = inputWithPolicy(onlySignature);

        // when
        SigningRecord signingRecord = mapper.toRecord(input);

        // then
        assertArrayEquals(input.getSignature(), signingRecord.getSignatureValue());
        assertNull(signingRecord.getRequestMetadataJson());
        assertNull(signingRecord.getSignedDocument());
        assertNull(signingRecord.getDtbs());
    }

    @Test
    void toRecord_recordsOnlySignedDocument_whenOnlyThatToggleEnabled() {
        // given
        SigningRecordPolicyModel onlySignedDocument = aSigningRecordPolicy().recordSignedDocument(true).build();
        SigningRecordInput input = inputWithPolicy(onlySignedDocument);

        // when
        SigningRecord signingRecord = mapper.toRecord(input);

        // then
        assertArrayEquals(input.getSignedDocument(), signingRecord.getSignedDocument());
        assertNull(signingRecord.getRequestMetadataJson());
        assertNull(signingRecord.getSignatureValue());
        assertNull(signingRecord.getDtbs());
    }

    @Test
    void toRecord_recordsOnlyDtbs_whenOnlyThatToggleEnabled() {
        // given
        SigningRecordPolicyModel onlyDtbs = aSigningRecordPolicy().recordDtbs(true).build();
        SigningRecordInput input = inputWithPolicy(onlyDtbs);

        // when
        SigningRecord signingRecord = mapper.toRecord(input);

        // then
        assertArrayEquals(input.getDtbs(), signingRecord.getDtbs());
        assertNull(signingRecord.getRequestMetadataJson());
        assertNull(signingRecord.getSignatureValue());
        assertNull(signingRecord.getSignedDocument());
    }

    @Test
    void toOutbox_copiesScalarFields() {
        // given
        var profileUuid = UUID.fromString("11111111-1111-1111-1111-111111111111");
        var profileVersion = 7;
        var signingTime = Instant.parse("2026-03-01T12:00:00Z");
        var displayName = "my-record";
        SigningProfileModel<?, ?> profile = aSigningProfile()
                .withUuid(profileUuid)
                .withVersion(profileVersion)
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
        assertEquals(UUID.fromString(input.getRequestedBy().getUuid()), outbox.getRequestedByUuid());
        assertEquals(input.getRequestedBy().getName(), outbox.getRequestedByUsername());
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

        // then the requester identity is captured unconditionally, independent of the content policy
        assertEquals(UUID.fromString(input.getRequestedBy().getUuid()), outbox.getRequestedByUuid());
        assertEquals(input.getRequestedBy().getName(), outbox.getRequestedByUsername());
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
                .signingProfile(aSigningProfile().withRecordPolicy(policy).build())
                .build();
    }
}
