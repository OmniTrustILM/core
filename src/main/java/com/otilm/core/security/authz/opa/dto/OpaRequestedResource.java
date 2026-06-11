package com.otilm.core.security.authz.opa.dto;

import com.fasterxml.jackson.annotation.JsonAnyGetter;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;

import java.util.List;
import java.util.Map;

@JsonInclude(JsonInclude.Include.NON_NULL)
public class OpaRequestedResource {

    private Map<String, String> properties;
    @JsonProperty("uuids")
    private List<String> objectUUIDs;
    @JsonProperty("parentUUIDs")
    private List<String> parentObjectUUIDs;
    @JsonProperty("url")
    private List<String> url;

    public OpaRequestedResource(Map<String, String> properties) {
        this.properties = properties;
    }

    public OpaRequestedResource(List<String> url) {
        this.url = url;
    }

    public void setObjectUUIDs(List<String> objectUUIDs) {
        this.objectUUIDs = objectUUIDs;
    }

    public void setParentObjectUUIDs(List<String> parentObjectUUIDs) {
        this.parentObjectUUIDs = parentObjectUUIDs;
    }

    @JsonAnyGetter
    public Map<String, String> getProperties() {
        return properties;
    }

    public void setProperties(Map<String, String> properties) {
        this.properties = properties;
    }

    public List<String> getObjectUUIDs() {
        return objectUUIDs;
    }

    public List<String> getParentObjectUUIDs() {
        return parentObjectUUIDs;
    }

    public List<String> getUrl() {
        return url;
    }


    @Override
    public String toString() {
        return "OpaRequestedResource{" +
                "properties=" + properties +
                ", objectUUIDs=" + objectUUIDs +
                ", parentObjectUUIDs=" + parentObjectUUIDs +
                ", url=" + url +
                '}';
    }
}
