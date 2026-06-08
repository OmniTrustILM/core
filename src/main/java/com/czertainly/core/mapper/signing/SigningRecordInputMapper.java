package com.czertainly.core.mapper.signing;

import com.czertainly.api.model.common.NameAndUuidDto;
import com.czertainly.core.dao.entity.signing.SigningRecord;
import com.czertainly.core.dao.entity.signing.SigningRecordOutbox;
import com.czertainly.core.model.signing.SigningRecordPolicyModel;
import com.czertainly.core.signing.record.SigningRecordInput;
import org.springframework.stereotype.Component;

import java.util.UUID;
import java.util.function.Consumer;

/**
 * Maps a {@link SigningRecordInput} to the entity each persistence strategy stores, applying the
 * per-field {@code record*} toggles of the profile's {@link SigningRecordPolicyModel} in one shared place.
 */
@Component
public class SigningRecordInputMapper {

    /**
     * Builds a fully populated {@link SigningRecord}, including its signing-profile UUID.
     */
    public SigningRecord toRecord(SigningRecordInput input) {
        SigningRecord record = new SigningRecord();
        record.setUuid(UUID.randomUUID());
        record.setName(input.getDisplayName());
        record.setSigningProfileUuid(input.getSigningProfile().uuid());
        record.setSigningProfileVersion(input.getSigningProfile().version());
        record.setSigningTime(input.getSigningTime());
        applyRequester(input, record::setRequestedByUuid, record::setRequestedByUsername);
        applyRecordableContent(input,
                record::setRequestMetadataJson, record::setSignatureValue,
                record::setSignedDocument, record::setDtbs);
        return record;
    }

    /**
     * Builds a fully populated {@link SigningRecordOutbox} row, including its signing-profile UUID.
     */
    public SigningRecordOutbox toOutbox(SigningRecordInput input) {
        SigningRecordOutbox outbox = new SigningRecordOutbox();
        outbox.setUuid(UUID.randomUUID());
        outbox.setName(input.getDisplayName());
        outbox.setSigningProfileUuid(input.getSigningProfile().uuid());
        outbox.setSigningProfileVersion(input.getSigningProfile().version());
        outbox.setSigningTime(input.getSigningTime());
        applyRequester(input, outbox::setRequestedByUuid, outbox::setRequestedByUsername);
        applyRecordableContent(input,
                outbox::setRequestMetadataJson, outbox::setSignatureValue,
                outbox::setSignedDocument, outbox::setDtbs);
        return outbox;
    }

    /**
     * Unpacks the requester {@link NameAndUuidDto} into the record's denormalized uuid/username columns.
     * Captured unconditionally — the requester identity is not gated by the content {@code record*} toggles.
     */
    private void applyRequester(SigningRecordInput input, Consumer<UUID> uuid, Consumer<String> username) {
        NameAndUuidDto requestedBy = input.getRequestedBy();
        if (requestedBy == null) {
            return;
        }
        if (requestedBy.getUuid() != null)
            uuid.accept(UUID.fromString(requestedBy.getUuid()));
        username.accept(requestedBy.getName());
    }

    private void applyRecordableContent(SigningRecordInput input,
                                        Consumer<String> requestMetadataJson,
                                        Consumer<byte[]> signature,
                                        Consumer<byte[]> signedDocument,
                                        Consumer<byte[]> dtbs) {
        SigningRecordPolicyModel policy = input.getSigningProfile().recordPolicy();
        if (policy.recordRequestMetadata())
            requestMetadataJson.accept(input.getRequestMetadataJson());
        if (policy.recordSignature())
            signature.accept(input.getSignature());
        if (policy.recordSignedDocument())
            signedDocument.accept(input.getSignedDocument());
        if (policy.recordDtbs())
            dtbs.accept(input.getDtbs());
    }
}
