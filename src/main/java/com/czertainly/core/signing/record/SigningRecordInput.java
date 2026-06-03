package com.czertainly.core.signing.record;

import com.czertainly.core.dao.entity.signing.SigningProfile;
import com.czertainly.core.dao.entity.signing.SigningProfileVersion;
import com.czertainly.core.model.signing.SigningProfileModel;
import com.czertainly.core.model.signing.scheme.SigningSchemeModel;
import com.czertainly.core.model.signing.workflow.SigningWorkflow;
import lombok.Builder;
import lombok.Value;

import java.time.Instant;
import java.time.OffsetDateTime;

@Value
@Builder
public class SigningRecordInput {
    SigningProfileModel<?, ?> signingProfile;
    Instant signingTime;
    String displayName;
    String requestMetadataJson;
    byte[] signature;
    byte[] signedDocument;
    byte[] dtbs;
}
