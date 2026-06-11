package com.otilm.core.security.authz;

import java.util.List;

public interface ParentUUIDGetter {
    List<String> getParentsUUID(List<String> objectsUUID);
}
