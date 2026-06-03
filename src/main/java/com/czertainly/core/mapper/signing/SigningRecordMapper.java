package com.czertainly.core.mapper.signing;

import com.czertainly.api.model.core.signing.signingrecord.SigningRecordDto;
import com.czertainly.api.model.core.signing.signingrecord.SigningRecordListDto;
import com.czertainly.core.dao.entity.signing.SigningRecord;

import java.time.Instant;
import java.time.OffsetDateTime;

public class SigningRecordMapper {

    private SigningRecordMapper() {
    }

    public static SigningRecordDto toDto(SigningRecord record) {
        SigningRecordDto dto = new SigningRecordDto();
        dto.setUuid(record.getUuid().toString());
        dto.setName(record.getName());
        Instant signingTimeZoned = record.getSigningTime() != null ? record.getSigningTime() : null;
        dto.setSigningTime(signingTimeZoned);
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
        Instant signingTime = record.getSigningTime() != null ? record.getSigningTime() : null;
        dto.setSigningTime(signingTime);
        OffsetDateTime createdAtZoned = record.getCreated();
        dto.setCreatedAt(createdAtZoned.toInstant());
        return dto;
    }
}
