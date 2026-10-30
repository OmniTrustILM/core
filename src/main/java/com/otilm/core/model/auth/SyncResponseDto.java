package com.otilm.core.model.auth;

import io.swagger.v3.oas.annotations.media.Schema;
import org.apache.commons.lang3.builder.ToStringBuilder;
import org.apache.commons.lang3.builder.ToStringStyle;

public class SyncResponseDto {

    @Schema(description = "List of resources")
    private SyncResourcesDto resources;

    @Schema(description = "List of Actions")
    private SyncActionsDto actions;

    public SyncResourcesDto getResources() {
        return resources;
    }

    public void setResources(SyncResourcesDto resources) {
        this.resources = resources;
    }

    public SyncActionsDto getActions() {
        return actions;
    }

    public void setActions(SyncActionsDto actions) {
        this.actions = actions;
    }

    @Override
    public String toString() {
        return new ToStringBuilder(this, ToStringStyle.SHORT_PREFIX_STYLE)
                .append("resources", resources)
                .append("actions", actions)
                .toString();
    }
}
