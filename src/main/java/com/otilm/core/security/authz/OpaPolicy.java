package com.otilm.core.security.authz;

public enum OpaPolicy {
    METHOD("method"),
    OBJECTS("objects");

    public final String policyName;

    OpaPolicy(String policyName) {
        this.policyName = policyName;
    }
}
