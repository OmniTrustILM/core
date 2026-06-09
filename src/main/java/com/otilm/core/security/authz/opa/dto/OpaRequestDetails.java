package com.otilm.core.security.authz.opa.dto;

import com.fasterxml.jackson.annotation.JsonProperty;

public class OpaRequestDetails {
    @JsonProperty("remoteAddress")
    String remoteAddress;

    public OpaRequestDetails(String remoteAddress) {
        this.remoteAddress = remoteAddress;
    }

    public String getRemoteAddress() {
        return remoteAddress;
    }

    @Override
    public String toString() {
        return "OpaRequestDetails{" +
                "remoteAddress='" + remoteAddress + '\'' +
                '}';
    }
}