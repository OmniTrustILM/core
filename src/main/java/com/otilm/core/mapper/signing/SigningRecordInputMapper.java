package com.otilm.core.mapper.signing;

import com.otilm.api.model.common.NameAndUuidDto;
import com.otilm.core.dao.entity.signing.SigningRecord;
import com.otilm.core.dao.entity.signing.SigningRecordOutbox;
import com.otilm.core.model.signing.SigningRecordPolicyModel;
import com.otilm.core.signing.record.SigningRecordInput;
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
        SigningRecord signingRecord = new SigningRecord();
        signingRecord.setUuid(UUID.randomUUID());
        signingRecord.setName(input.getDisplayName());
        signingRecord.setSigningProfileUuid(input.getSigningProfile().uuid());
        signingRecord.setSigningProfileVersion(input.getSigningProfile().version());
        signingRecord.setSigningTime(input.getSigningTime());
        signingRecord.setProtocol(input.getProtocol());
        applyRequester(input, signingRecord::setRequestedByUuid, signingRecord::setRequestedByUsername);
        applyRecordableContent(input,
                signingRecord::setRequestMetadataJson, signingRecord::setSignatureValue,
                signingRecord::setSignedDocument, signingRecord::setDtbs);
        return signingRecord;
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
        outbox.setProtocol(input.getProtocol());
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
