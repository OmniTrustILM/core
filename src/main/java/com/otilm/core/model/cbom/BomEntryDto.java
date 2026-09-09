package com.otilm.core.model.cbom;

import com.fasterxml.jackson.annotation.JsonProperty;
import io.swagger.v3.oas.annotations.media.Schema;
import jakarta.validation.constraints.NotNull;
import java.time.OffsetDateTime;
import java.util.List;
import lombok.Getter;
import lombok.Setter;
import org.apache.commons.lang3.builder.ToStringBuilder;
import org.apache.commons.lang3.builder.ToStringStyle;

/**
 * One entry of the cbom-repository search feed ({@code GET /api/v1/bom}), contract 0.3.0.
 *
 * <p>
 * The wire name of the creation time is {@code created_at} (snake case, unlike every other field). In paged mode
 * ({@code limit} sent) an object whose stored statistics are missing or unreadable is still listed, with
 * {@code cryptoStats} null and the reason in {@code warnings}; the unpaged call never emits either. The warning codes
 * are {@code crypto-stats-missing} and {@code crypto-stats-invalid} (no counts, {@code cryptoStats} null),
 * {@code crypto-stats-shallow} (top-level components only) and {@code crypto-stats-truncated} (cut off at the
 * repository's depth bound); the sync logs them as sent and does not branch on them.
 */
@Setter
@Getter
@Schema(description = "BOM entry")
public class BomEntryDto {

    @NotNull
    @Schema(description = "BOM serial number", example = "urn:uuid:3e671687-395b-41f5-a30f-a58921a69b79",
            requiredMode = Schema.RequiredMode.REQUIRED)
    private String serialNumber;

    @NotNull
    @Schema(description = "BOM Version - number or `original` string", example = "1",
            requiredMode = Schema.RequiredMode.REQUIRED)
    private String version;

    @JsonProperty("created_at")
    @Schema(description = "RFC 3339 timestamp (UTC, second precision) when this document version was stored",
            example = "2026-01-25T21:35:05Z", requiredMode = Schema.RequiredMode.REQUIRED)
    private OffsetDateTime createdAt;

    @Schema(description = "Crypto statistics; null in paged mode when the stored statistics could not be read, see warnings",
            requiredMode = Schema.RequiredMode.NOT_REQUIRED)
    private CryptoStatsDto cryptoStats;

    @Schema(description = "Paged mode only: crypto-stats-missing, crypto-stats-invalid, crypto-stats-shallow, crypto-stats-truncated",
            requiredMode = Schema.RequiredMode.NOT_REQUIRED)
    private List<String> warnings;

    public boolean hasWarnings() {
        return warnings != null && !warnings.isEmpty();
    }

    @Override
    public String toString() {
        return new ToStringBuilder(this, ToStringStyle.SHORT_PREFIX_STYLE)
                .append("serialNumber", serialNumber)
                .append("version", version)
                .append("warnings", warnings)
                .toString();
    }
}
