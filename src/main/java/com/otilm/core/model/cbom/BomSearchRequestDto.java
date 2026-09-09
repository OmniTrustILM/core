package com.otilm.core.model.cbom;

import io.swagger.v3.oas.annotations.media.Schema;
import lombok.Getter;
import lombok.Setter;
import org.apache.commons.lang3.builder.ToStringBuilder;
import org.apache.commons.lang3.builder.ToStringStyle;

@Setter
@Getter
@Schema(description = "Search BOMs created after a timestamp")
public class BomSearchRequestDto {

    @Schema(description = "Unix timestamp (seconds); documents created strictly after it are listed. Null means 0.",
            example = "1769156084", requiredMode = Schema.RequiredMode.NOT_REQUIRED)
    private Long after;

    @Schema(description = "Page size 1..1000 sent as `limit`. Null selects the unpaged legacy call, which never pages.",
            example = "1000", requiredMode = Schema.RequiredMode.NOT_REQUIRED)
    private Integer limit;

    @Override
    public String toString() {
        return new ToStringBuilder(this, ToStringStyle.SHORT_PREFIX_STYLE)
                .append("after", after)
                .append("limit", limit)
                .toString();
    }
}
