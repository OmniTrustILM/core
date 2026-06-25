package com.otilm.core.oid;

import jakarta.validation.constraints.NotNull;
import lombok.Builder;

import java.util.List;

@Builder
public record OidRecord(
        @NotNull String displayName,
        String code,
        List<String> altCodes
) {
}
