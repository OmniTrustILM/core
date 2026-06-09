package com.otilm.core.security.authz.opa.dto;

import com.fasterxml.jackson.annotation.JsonProperty;

public class AnonymousPrincipal {
    @JsonProperty("user")
    private AnonymousUser user;

    public AnonymousPrincipal(String user) {
        this.user =  new AnonymousUser(user);
    }

    public AnonymousUser getUser() {
        return user;
    }

    public static class AnonymousUser {

        private final String username;

        public AnonymousUser(String username) {
            this.username = username;
        }

        @JsonProperty("username")
        public String getUsername() {
            return username;
        }
    }

}
