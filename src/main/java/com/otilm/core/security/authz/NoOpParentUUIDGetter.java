package com.otilm.core.security.authz;

import org.apache.commons.lang3.NotImplementedException;

import java.util.List;

public class NoOpParentUUIDGetter implements ParentUUIDGetter {
    @Override
    public List<String> getParentsUUID(List<String> objectsUUID) {
        throw new NotImplementedException("To get the parent uuid of a specific object type, use the implementation specific to that object.");
    }
}
