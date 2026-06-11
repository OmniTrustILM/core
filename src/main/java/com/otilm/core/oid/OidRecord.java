package com.otilm.core.oid;

import jakarta.validation.constraints.NotNull;

import java.util.List;

public record OidRecord(
        @NotNull String displayName,
        String code,
        List<String> altCodes
) {
}
