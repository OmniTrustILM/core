package com.czertainly.core.mapper.signing;

import com.czertainly.api.model.core.signing.signingrecord.SigningRecordDto;
import com.czertainly.api.model.core.signing.signingrecord.SigningRecordListDto;
import com.czertainly.core.dao.entity.signing.SigningRecord;

import java.time.ZonedDateTime;

public class SigningRecordMapper {

    private SigningRecordMapper() {
    }

    public static SigningRecordDto toDto(SigningRecord record) {
        SigningRecordDto dto = new SigningRecordDto();
        dto.setUuid(record.getUuid().toString());
        dto.setName(record.getName());
        ZonedDateTime signingTimeZoned = record.getSigningTime() != null ? record.getSigningTime().toZonedDateTime() : null;
        dto.setSigningTime(signingTimeZoned);
        ZonedDateTime createdAtZoned = record.getCreatedAt() != null ? record.getCreatedAt().toZonedDateTime() : null;
        dto.setCreatedAt(createdAtZoned);
        dto.setSignatureValue(record.getSignatureValue());
        dto.setSignedDocument(record.getSignedDocument());
        dto.setDtbs(record.getDtbs());
        dto.setRequestMetadataJson(record.getRequestMetadataJson());
        if (record.getSignedDocumentRetrievedAt() != null) {
            dto.setSignedDocumentRetrievedAt(record.getSignedDocumentRetrievedAt().toZonedDateTime());
        }
        return dto;
    }

    public static SigningRecordListDto toListDto(SigningRecord record) {
        SigningRecordListDto dto = new SigningRecordListDto();
        dto.setUuid(record.getUuid().toString());
        dto.setName(record.getName());
        ZonedDateTime signingTimeZoned = record.getSigningTime() != null ? record.getSigningTime().toZonedDateTime() : null;
        dto.setSigningTime(signingTimeZoned);
        ZonedDateTime createdAtZoned = record.getCreatedAt() != null ? record.getCreatedAt().toZonedDateTime() : null;
        dto.setCreatedAt(createdAtZoned);
        return dto;
    }
}
