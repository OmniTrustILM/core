package com.otilm.core.service.est.enrollment;

import com.fasterxml.jackson.annotation.JsonValue;
import com.otilm.core.dao.entity.est.EstProfile;

/** Where the key of a server-side key generation lives once the answer is built. */
public enum EstServerKeyGenerationMode {
    /** Only in the memory of the request: nothing keeps the key. */
    IN_MEMORY("in-memory"),
    /** On the key-recovery token profile of the EST Profile, which keeps the key to be exported again. */
    KEY_RECOVERY("key-recovery");

    private final String code;

    EstServerKeyGenerationMode(String code) {
        this.code = code;
    }

    static EstServerKeyGenerationMode of(EstProfile estProfile) {
        return estProfile.isKeyRecovery() ? KEY_RECOVERY : IN_MEMORY;
    }

    @JsonValue
    public String getCode() {
        return code;
    }
}
