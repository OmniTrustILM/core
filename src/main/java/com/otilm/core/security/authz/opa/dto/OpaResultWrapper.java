package com.otilm.core.security.authz.opa.dto;

import com.fasterxml.jackson.annotation.JsonProperty;

public class OpaResultWrapper<T> {
    @JsonProperty("result")
    private T result;

    public T getResult() {
        return result;
    }

    public void setResult(T result) {
        this.result = result;
    }
}
