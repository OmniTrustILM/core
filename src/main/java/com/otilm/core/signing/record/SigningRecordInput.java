package com.otilm.core.signing.record;

import com.otilm.api.model.common.NameAndUuidDto;
import com.otilm.api.model.core.signing.SigningProtocol;
import com.otilm.core.model.signing.SigningProfileModel;
import lombok.Builder;
import lombok.Value;

import java.time.Instant;

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
}
