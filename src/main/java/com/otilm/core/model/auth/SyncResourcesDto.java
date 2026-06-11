package com.otilm.core.model.auth;

import io.swagger.v3.oas.annotations.media.Schema;
import org.apache.commons.lang3.builder.ToStringBuilder;
import org.apache.commons.lang3.builder.ToStringStyle;

import java.util.List;

public class SyncResourcesDto {

    @Schema(description = "List of new resources added")
    private List<String> added;

    @Schema(description = "List of resources updated")
    private List<String> updated;

    @Schema(description = "List of resources removed")
    private List<String> removed;

    public List<String> getAdded() {
        return added;
    }

    public void setAdded(List<String> added) {
        this.added = added;
    }

    public List<String> getUpdated() {
        return updated;
    }

    public void setUpdated(List<String> updated) {
        this.updated = updated;
    }

    public List<String> getRemoved() {
        return removed;
    }

    public void setRemoved(List<String> removed) {
        this.removed = removed;
    }

    @Override
    public String toString() {
        return new ToStringBuilder(this, ToStringStyle.SHORT_PREFIX_STYLE)
                .append("added", added)
                .append("updated", updated)
                .append("removed", removed)
                .toString();
    }
}
