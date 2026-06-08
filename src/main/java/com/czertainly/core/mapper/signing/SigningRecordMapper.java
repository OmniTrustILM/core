package com.czertainly.core.mapper.signing;

import com.czertainly.api.model.client.signing.profile.SigningProfileListDto;
import com.czertainly.api.model.core.signing.signingrecord.SigningRecordDto;
import com.czertainly.api.model.core.signing.signingrecord.SigningRecordListDto;
import com.czertainly.core.dao.entity.signing.SigningProfile;
import com.czertainly.core.dao.entity.signing.SigningRecord;
import com.czertainly.core.dao.entity.signing.SigningRecordOutbox;

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
        SigningRecord record = new SigningRecord();
        record.setUuid(outbox.getUuid());
        record.setName(outbox.getName());
        record.setSigningProfileUuid(outbox.getSigningProfileUuid());
        record.setSigningProfileVersion(outbox.getSigningProfileVersion());
        record.setSigningTime(outbox.getSigningTime());
        record.setSignatureValue(outbox.getSignatureValue());
        record.setSignedDocument(outbox.getSignedDocument());
        record.setDtbs(outbox.getDtbs());
        record.setRequestMetadataJson(outbox.getRequestMetadataJson());
        return record;
    }

    public static SigningRecordDto toDto(SigningRecord record) {
        SigningRecordDto dto = new SigningRecordDto();
        dto.setUuid(record.getUuid().toString());
        dto.setName(record.getName());
        dto.setSigningProfile(toSigningProfileListDto(record));
        Instant signingTime = record.getSigningTime();
        dto.setSigningTime(signingTime);
        OffsetDateTime createdAt = record.getCreated();
        dto.setCreatedAt(createdAt.toInstant());
        dto.setSignatureValue(record.getSignatureValue());
        dto.setSignedDocument(record.getSignedDocument());
        dto.setDtbs(record.getDtbs());
        dto.setRequestMetadataJson(record.getRequestMetadataJson());
        if (record.getSignedDocumentRetrievedAt() != null) {
            dto.setSignedDocumentRetrievedAt(record.getSignedDocumentRetrievedAt());
        }
        return dto;
    }

    public static SigningRecordListDto toListDto(SigningRecord record) {
        SigningRecordListDto dto = new SigningRecordListDto();
        dto.setUuid(record.getUuid().toString());
        dto.setName(record.getName());
        Instant signingTime = record.getSigningTime();
        dto.setSigningTime(signingTime);
        OffsetDateTime createdAtZoned = record.getCreated();
        dto.setCreatedAt(createdAtZoned.toInstant());
        dto.setSigningProfile(toSigningProfileListDto(record));
        return dto;
    }

    /**
     * Builds the {@link SigningProfileListDto} for a record's detail view. The version is pinned to the
     * {@code signingProfileVersion} captured when the record was produced — not the profile's current latest
     * version — so the DTO reflects the profile state that actually produced this signature.
     */
    private static SigningProfileListDto toSigningProfileListDto(SigningRecord record) {
        SigningProfile profile = record.getSigningProfile();
        if (profile == null) {
            return null;
        }
        SigningProfileListDto dto = SigningProfileMapper.toListDto(profile);
        dto.setVersion(record.getSigningProfileVersion());
        return dto;
    }
}
