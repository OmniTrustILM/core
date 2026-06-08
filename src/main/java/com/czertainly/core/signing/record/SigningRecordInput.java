package com.czertainly.core.signing.record;

import com.czertainly.api.model.common.NameAndUuidDto;
import com.czertainly.core.model.signing.SigningProfileModel;
import lombok.Builder;
import lombok.Value;

import java.time.Instant;

@Value
@Builder
public class SigningRecordInput {
    SigningProfileModel<?, ?> signingProfile;
    Instant signingTime;
    NameAndUuidDto requestedBy;
    String displayName;
    String requestMetadataJson;
    byte[] signature;
    byte[] signedDocument;
    byte[] dtbs;
}
