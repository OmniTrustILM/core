package com.otilm.core.reference;

import com.otilm.api.model.core.auth.Resource;
import java.util.Optional;
import java.util.UUID;

/**
 * A resource whose objects keep attribute values for every version reports the version in use, so that only the
 * references in that version keep the referenced object from being deleted.
 */
public interface CurrentVersionSource {

    Resource resource();

    /** Empty when the object no longer exists. */
    Optional<Integer> currentVersion(UUID objectUuid);
}
