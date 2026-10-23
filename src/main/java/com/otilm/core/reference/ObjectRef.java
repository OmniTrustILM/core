package com.otilm.core.reference;

import com.otilm.api.model.core.auth.Resource;
import java.util.UUID;

/**
 * One object of a resource, named by type so references between resources can be compared.
 */
public record ObjectRef(Resource resource, UUID uuid) {
}
