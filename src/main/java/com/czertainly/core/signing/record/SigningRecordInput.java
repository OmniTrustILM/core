package com.czertainly.core.signing.record;

import com.czertainly.core.dao.entity.signing.SigningProfile;
import com.czertainly.core.dao.entity.signing.SigningProfileVersion;
import lombok.Builder;
import lombok.Value;

import java.time.OffsetDateTime;

@Value
@Builder
public class SigningRecordInput {
    SigningProfile profile;
    SigningProfileVersion version;
    OffsetDateTime signingTime;
    String displayName;
    String requestMetadataJson;
    byte[] signature;
    byte[] signedDocument;
    byte[] dtbs;
}
