package com.otilm.core.security.authz;


import java.util.List;

public class GroupParentUUIDGetter implements ParentUUIDGetter {

    @Override
    // TODO AUTH - add real implementation
    public List<String> getParentsUUID(List<String> objectsUUID) {
        return List.of("123");
    }
}
