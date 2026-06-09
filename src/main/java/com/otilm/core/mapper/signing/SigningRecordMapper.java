package com.otilm.core.mapper.signing;

import com.otilm.api.model.client.signing.profile.SigningProfileListDto;
import com.otilm.api.model.common.NameAndUuidDto;
import com.otilm.api.model.core.signing.signingrecord.SigningRecordDto;
import com.otilm.api.model.core.signing.signingrecord.SigningRecordListDto;
import com.otilm.core.dao.entity.signing.SigningProfile;
import com.otilm.core.dao.entity.signing.SigningRecord;
import com.otilm.core.dao.entity.signing.SigningRecordOutbox;

import java.time.Instant;
import java.time.OffsetDateTime;

public class SigningRecordMapper {

    private SigningRecordMapper() {
    }

    /**
     * Copies a staged {@link SigningRecordOutbox} row into the {@link SigningRecord} the outbox drainer persists.
     * This is a straight field copy under the row's own UUID — the record-policy toggles were already applied
     * when the row was staged, so no content gating happens here.
     */
    public static SigningRecord toRecord(SigningRecordOutbox outbox) {
        SigningRecord signingRecord = new SigningRecord();
        signingRecord.setUuid(outbox.getUuid());
        signingRecord.setName(outbox.getName());
        signingRecord.setSigningProfileUuid(outbox.getSigningProfileUuid());
        signingRecord.setSigningProfileVersion(outbox.getSigningProfileVersion());
        signingRecord.setSigningTime(outbox.getSigningTime());
        signingRecord.setRequestedByUuid(outbox.getRequestedByUuid());
        signingRecord.setRequestedByUsername(outbox.getRequestedByUsername());
        signingRecord.setSignatureValue(outbox.getSignatureValue());
        signingRecord.setSignedDocument(outbox.getSignedDocument());
        signingRecord.setDtbs(outbox.getDtbs());
        signingRecord.setRequestMetadataJson(outbox.getRequestMetadataJson());
        return signingRecord;
    }

    public static SigningRecordDto toDto(SigningRecord signingRecord) {
        SigningRecordDto dto = new SigningRecordDto();
        dto.setUuid(signingRecord.getUuid().toString());
        dto.setName(signingRecord.getName());
        dto.setSigningProfile(toSigningProfileListDto(signingRecord));
        Instant signingTime = signingRecord.getSigningTime();
        dto.setSigningTime(signingTime);
        if (signingRecord.getRequestedByUuid() != null) {
            dto.setRequestedBy(new NameAndUuidDto(
                    signingRecord.getRequestedByUuid().toString(), signingRecord.getRequestedByUsername()));
        }
        OffsetDateTime createdAt = signingRecord.getCreated();
        dto.setCreatedAt(createdAt.toInstant());
        dto.setSignatureValue(signingRecord.getSignatureValue());
        dto.setSignedDocument(signingRecord.getSignedDocument());
        dto.setDtbs(signingRecord.getDtbs());
        dto.setRequestMetadataJson(signingRecord.getRequestMetadataJson());
        if (signingRecord.getSignedDocumentRetrievedAt() != null) {
            dto.setSignedDocumentRetrievedAt(signingRecord.getSignedDocumentRetrievedAt());
        }
        return dto;
    }

    public static SigningRecordListDto toListDto(SigningRecord signingRecord) {
        SigningRecordListDto dto = new SigningRecordListDto();
        dto.setUuid(signingRecord.getUuid().toString());
        dto.setName(signingRecord.getName());
        Instant signingTime = signingRecord.getSigningTime();
        dto.setSigningTime(signingTime);
        OffsetDateTime createdAtZoned = signingRecord.getCreated();
        dto.setCreatedAt(createdAtZoned.toInstant());
        dto.setSigningProfile(toSigningProfileListDto(signingRecord));
        return dto;
    }

    /**
     * Builds the {@link SigningProfileListDto} for a record's detail view. The version is pinned to the
     * {@code signingProfileVersion} captured when the record was produced — not the profile's current latest
     * version — so the DTO reflects the profile state that actually produced this signature.
     */
    private static SigningProfileListDto toSigningProfileListDto(SigningRecord signingRecord) {
        SigningProfile profile = signingRecord.getSigningProfile();
        if (profile == null) {
            throw new IllegalStateException(
                    "SigningRecord " + signingRecord.getUuid() + " has no signing profile; signing_profile_uuid is NOT NULL "
                            + "and SigningRecordDto.signingProfile is required, so this association must be present.");
        }
        SigningProfileListDto dto = SigningProfileMapper.toListDto(profile);
        dto.setVersion(signingRecord.getSigningProfileVersion());
        return dto;
    }
}
