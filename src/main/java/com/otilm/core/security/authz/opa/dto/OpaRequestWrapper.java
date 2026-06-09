package com.otilm.core.security.authz.opa.dto;

import com.fasterxml.jackson.annotation.JsonProperty;

/**
 * A wrapper that wraps all the requests to the opa into an object with only one property 'input', as required by OPA.
 *
 * @param <T> Inner data
 */
public class OpaRequestWrapper<T> {
    @JsonProperty("input")
    public T input;

    public OpaRequestWrapper(T input) {
        this.input = input;
    }

}