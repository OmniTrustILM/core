package com.otilm.core.security.authn.client.dto;

import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.databind.annotation.JsonDeserialize;
import com.otilm.core.util.RawJsonDeserializer;

public class AuthenticationResponseDto {

    @JsonProperty("authenticated")
    private boolean authenticated;
    @JsonDeserialize(using = RawJsonDeserializer.class)
    @JsonProperty("data")
    String data;

    public AuthenticationResponseDto() {
    }

    public String getData() {
        return data;
    }

    public boolean isAuthenticated() {
        return authenticated;
    }
}
