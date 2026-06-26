package com.otilm.core.oid;

import com.otilm.api.model.core.oid.ExtensionValueEncoding;
import jakarta.validation.constraints.NotNull;
import lombok.Builder;

import java.util.List;

@Builder
public record OidRecord(
        @NotNull String displayName,
        String code,
        List<String> altCodes,
        Boolean defaultCritical,
        ExtensionValueEncoding valueEncoding
) {
}
