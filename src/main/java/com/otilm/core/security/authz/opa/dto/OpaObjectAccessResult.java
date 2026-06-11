package com.otilm.core.security.authz.opa.dto;

import com.fasterxml.jackson.annotation.JsonProperty;

import java.util.List;

public class OpaObjectAccessResult {
    @JsonProperty("allowedObjects")
    private List<String> allowedObjects;
    @JsonProperty("forbiddenObjects")
    private List<String> forbiddenObjects;
    @JsonProperty("actionAllowedForGroupOfObjects")
    private boolean actionAllowedForGroupOfObjects;

    public List<String> getAllowedObjects() {
        return allowedObjects;
    }

    public void setAllowedObjects(List<String> allowedObjects) {
        this.allowedObjects = allowedObjects;
    }

    public List<String> getForbiddenObjects() {
        return forbiddenObjects;
    }

    public void setForbiddenObjects(List<String> forbiddenObjects) {
        this.forbiddenObjects = forbiddenObjects;
    }

    public boolean isActionAllowedForGroupOfObjects() {
        return actionAllowedForGroupOfObjects;
    }

    public void setActionAllowedForGroupOfObjects(boolean actionAllowedForGroupOfObjects) {
        this.actionAllowedForGroupOfObjects = actionAllowedForGroupOfObjects;
    }

    @Override
    public String toString() {
        return 
                "allowedObjects=%s, forbiddenObjects=%s, actionAllowedForGroupOfObjects=%b".formatted(
                String.join(",", this.allowedObjects),
                String.join(",", this.forbiddenObjects),
                actionAllowedForGroupOfObjects
        );
    }
}
