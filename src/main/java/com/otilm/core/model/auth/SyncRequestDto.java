package com.otilm.core.model.auth;

import com.otilm.api.model.core.auth.Resource;
import com.otilm.core.model.auth.ResourceAction;
import io.swagger.v3.oas.annotations.media.Schema;
import org.apache.commons.lang3.builder.ToStringBuilder;
import org.apache.commons.lang3.builder.ToStringStyle;

public class SyncRequestDto {
    @Schema(description = "Name of the method", requiredMode = Schema.RequiredMode.REQUIRED, example = "listClient")
    private String name;

    @Schema(description = "Request Method", requiredMode = Schema.RequiredMode.REQUIRED, example = "GET")
    private String method;

    @Schema(description = "Context of the request", requiredMode = Schema.RequiredMode.REQUIRED, example = "/v1/clients")
    private String routeTemplate;

    @Schema(description = "Name of the resource", requiredMode = Schema.RequiredMode.REQUIRED, example = "client")
    private Resource resourceName;

    @Schema(description = "Action Name", requiredMode = Schema.RequiredMode.REQUIRED, example = "list")
    private ResourceAction actionName;

    @Schema(description = "Is endpoint for listing objects flag - true = Yes; false = No", requiredMode = Schema.RequiredMode.REQUIRED, example = "false", defaultValue = "false")
    private boolean isListingEndpoint;

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }

    public String getMethod() {
        return method;
    }

    public void setMethod(String method) {
        this.method = method;
    }

    public String getRouteTemplate() {
        return routeTemplate;
    }

    public void setRouteTemplate(String routeTemplate) {
        this.routeTemplate = routeTemplate;
    }

    public Resource getResourceName() {
        return resourceName;
    }

    public void setResourceName(Resource resourceName) {
        this.resourceName = resourceName;
    }

    public ResourceAction getActionName() {
        return actionName;
    }

    public void setActionName(ResourceAction actionName) {
        this.actionName = actionName;
    }

    public boolean getIsListingEndpoint() {
        return isListingEndpoint;
    }

    public void setIsListingEndpoint(boolean isListingEndpoint) {
        this.isListingEndpoint = isListingEndpoint;
    }

    @Override
    public String toString() {
        return new ToStringBuilder(this, ToStringStyle.SHORT_PREFIX_STYLE)
                .append("name", name)
                .append("method", method)
                .append("routeTemplate", routeTemplate)
                .append("resourceName", resourceName)
                .append("actionName", actionName)
                .append("isListingEndpoint", isListingEndpoint)
                .toString();
    }
}
