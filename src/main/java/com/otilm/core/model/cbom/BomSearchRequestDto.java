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

        @Schema(
                description = "Unix timestamp",
                example = "1769156084",
                requiredMode = Schema.RequiredMode.NOT_REQUIRED
        )
        private Long after;

        @Override
        public String toString() {
                return new ToStringBuilder(this, ToStringStyle.SHORT_PREFIX_STYLE)
                .append("after", after)
                .toString();
        }
}

