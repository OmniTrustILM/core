package com.otilm.core.security.authn.client.dto;

import com.otilm.api.model.common.NameAndUuidDto;
import com.fasterxml.jackson.annotation.JsonProperty;

import java.util.Collection;

public class UserDetailsDto {
    @JsonProperty("user")
    UserDto user;
    @JsonProperty("roles")
    Collection<NameAndUuidDto> roles;

    public UserDetailsDto() {
    }

    public UserDto getUser() {
        return user;
    }

    public Collection<NameAndUuidDto> getRoles() {
        return roles;
    }
}
