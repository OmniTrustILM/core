package com.otilm.core.util;

public enum SecretEncodingVersion {
    V1("v1");

    private String version;

    SecretEncodingVersion(String version) {
        this.version = version;
    }

    public String getVersion() {
        return version;
    }

}
