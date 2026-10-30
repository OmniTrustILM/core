package com.otilm.core.signing.record;

import com.otilm.api.model.common.NameAndUuidDto;
import com.otilm.api.model.core.signing.SigningProtocol;
import com.otilm.core.model.signing.SigningProfileModel;
import java.time.Instant;
import java.util.List;
import lombok.Builder;
import lombok.Value;

@Value
@Builder
public class SigningRecordInput {
    SigningProfileModel<?, ?> signingProfile;
    SigningProtocol protocol;
    Instant signingTime;
    NameAndUuidDto requestedBy;
    String displayName;
    String requestMetadataJson;
    byte[] signature;
    byte[] signedDocument;
    byte[] dtbs;
    List<String> timestampTokenSerialNumbers;
}
