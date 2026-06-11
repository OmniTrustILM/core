package com.otilm.core.model.auth;

import io.swagger.v3.oas.annotations.media.Schema;
import org.apache.commons.lang3.builder.ToStringBuilder;
import org.apache.commons.lang3.builder.ToStringStyle;

import java.util.List;

public class ResourceSyncRequestDto {

    @Schema(description = "Name of the resource", requiredMode = Schema.RequiredMode.REQUIRED, example = "client")
    private Resource name;

    @Schema(description = "Action Names", requiredMode = Schema.RequiredMode.REQUIRED, example = "list")
    private List<String> actions;

    @Schema(description = "Is endpoint for listing objects flag - true = Yes; false = No", requiredMode = Schema.RequiredMode.REQUIRED)
    private String listObjectsEndpoint;

    public Resource getName() {
        return name;
    }

    public void setName(Resource name) {
        this.name = name;
    }

    public List<String> getActions() {
        return actions;
    }

    public void setActions(List<String> actions) {
        this.actions = actions;
    }

    public String getListObjectsEndpoint() {
        return listObjectsEndpoint;
    }

    public void setListObjectsEndpoint(String listObjectsEndpoint) {
        this.listObjectsEndpoint = listObjectsEndpoint;
    }

    @Override
    public String toString() {
        return new ToStringBuilder(this, ToStringStyle.SHORT_PREFIX_STYLE)
                .append("resourceName", name)
                .append("actions", actions)
                .append("listObjectsEndpoint", listObjectsEndpoint)
                .toString();
    }
}
