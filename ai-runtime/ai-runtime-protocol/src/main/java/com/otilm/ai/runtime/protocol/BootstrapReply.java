package com.otilm.ai.runtime.protocol;

import com.fasterxml.jackson.annotation.JsonSubTypes;
import com.fasterxml.jackson.annotation.JsonTypeInfo;

@JsonTypeInfo(use = JsonTypeInfo.Id.NAME, property = "status")
@JsonSubTypes({
        @JsonSubTypes.Type(value = BootstrapClaimedReply.class, name = "claimed"),
        @JsonSubTypes.Type(value = BootstrapPendingReply.class, name = "pending")})
public sealed interface BootstrapReply permits BootstrapClaimedReply, BootstrapPendingReply {
    int protocolVersion();
}
