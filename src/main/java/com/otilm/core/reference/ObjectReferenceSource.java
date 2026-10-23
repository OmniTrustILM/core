package com.otilm.core.reference;

import com.otilm.api.model.core.auth.Resource;
import java.util.List;
import java.util.Set;

/**
 * A feature that stores references to objects of other resources reports them to the guard that refuses deleting a
 * referenced object.
 */
public interface ObjectReferenceSource {

    Set<Resource> referencedResources();

    /** Every referrer, whatever the caller may see; the guard decides which of them a refusal discloses. */
    List<ObjectReferrer> findReferrers(ObjectRef referenced);
}
