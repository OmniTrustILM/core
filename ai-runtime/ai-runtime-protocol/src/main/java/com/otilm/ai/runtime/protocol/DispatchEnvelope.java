package com.otilm.ai.runtime.protocol;

import com.fasterxml.jackson.annotation.JsonSubTypes;
import com.fasterxml.jackson.annotation.JsonTypeInfo;
import java.util.UUID;

@JsonTypeInfo(use = JsonTypeInfo.Id.NAME, property = "kind")
@JsonSubTypes({
        @JsonSubTypes.Type(value = RunDispatchEnvelope.class, name = "run"),
        @JsonSubTypes.Type(value = ManagementDispatchEnvelope.class, name = "management")})
public sealed interface DispatchEnvelope permits RunDispatchEnvelope, ManagementDispatchEnvelope {
    int protocolVersion();

    UUID intentId();

    String payloadSha256();
}
