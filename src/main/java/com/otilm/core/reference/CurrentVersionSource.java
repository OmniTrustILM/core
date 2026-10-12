package com.otilm.core.reference;

import com.otilm.api.model.core.auth.Resource;
import java.util.Optional;
import java.util.UUID;

/**
 * A resource that keeps attribute values for every version of its objects. Only the current version's values hold
 * references that refuse a delete.
 */
public interface CurrentVersionSource {

    Resource resource();

    /** Empty when the object no longer exists. */
    Optional<Integer> currentVersion(UUID objectUuid);
}
