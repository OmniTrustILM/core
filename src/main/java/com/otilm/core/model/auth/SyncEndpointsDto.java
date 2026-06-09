package com.otilm.core.model.auth;

import com.otilm.api.model.core.connector.EndpointDto;
import io.swagger.v3.oas.annotations.media.Schema;
import org.apache.commons.lang3.builder.ToStringBuilder;
import org.apache.commons.lang3.builder.ToStringStyle;

import java.util.List;

public class SyncEndpointsDto {
    @Schema(description = "List of end points added")
    private List<EndpointDto> added;

    @Schema(description = "List of end points updated")
    private List<EndpointDto> updated;

    @Schema(description = "List of end points removed")
    private List<EndpointDto> removed;

    public List<EndpointDto> getAdded() {
        return added;
    }

    public void setAdded(List<EndpointDto> added) {
        this.added = added;
    }

    public List<EndpointDto> getUpdated() {
        return updated;
    }

    public void setUpdated(List<EndpointDto> updated) {
        this.updated = updated;
    }

    public List<EndpointDto> getRemoved() {
        return removed;
    }

    public void setRemoved(List<EndpointDto> removed) {
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
