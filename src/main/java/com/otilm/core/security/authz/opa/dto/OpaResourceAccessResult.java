package com.otilm.core.security.authz.opa.dto;

import com.fasterxml.jackson.annotation.JsonProperty;

import java.util.Collections;
import java.util.List;

public class OpaResourceAccessResult {

    public static OpaResourceAccessResult unauthorized() {
        return new OpaResourceAccessResult(false, Collections.emptyList());
    }

    @JsonProperty("allow")
    private List<String> allow;
    @JsonProperty("authorized")
    private boolean authorized;


    public OpaResourceAccessResult(Boolean authorized, List<String> allow) {
        this.allow = allow;
        this.authorized = authorized;
    }

    public OpaResourceAccessResult() {
    }

    public List<String> getAllow() {
        return allow;
    }

    public void setAllow(List<String> allow) {
        this.allow = allow;
    }

    public boolean isAuthorized() {
        return authorized;
    }

    public void setAuthorized(boolean authorized) {
        this.authorized = authorized;
    }
}