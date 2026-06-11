package com.otilm.core.security.authz.opa.dto;

import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.annotation.JsonRawValue;

public class OpaInput {
    @JsonProperty("requestedResource")
    OpaRequestedResource requestedResource;
    @JsonProperty("details")
    OpaRequestDetails details;
    @JsonProperty("principal")
    @JsonRawValue
    String principal;

    public OpaInput(OpaRequestedResource requested_resource, String principal, OpaRequestDetails details) {
        this.requestedResource = requested_resource;
        this.principal = principal;
        this.details = details;
    }

    public String getPrincipal() {
        return principal;
    }
}

