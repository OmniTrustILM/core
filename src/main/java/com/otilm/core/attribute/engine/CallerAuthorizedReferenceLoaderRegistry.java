package com.otilm.core.attribute.engine;

import com.otilm.api.model.core.auth.AttributeResource;
import com.otilm.core.service.AuthorityInstanceInternalService;
import com.otilm.core.service.CredentialInternalService;
import com.otilm.core.service.EntityInstanceInternalService;
import com.otilm.core.service.LocationInternalService;
import org.springframework.stereotype.Component;

import java.util.EnumMap;
import java.util.Map;

/**
 * Typed {@code AttributeResource -> SecuredUUID-guarded loader} registry. Callback-mode
 * expansion resolves <strong>only</strong> through this map, and every value is a {@link CallerAuthorizedReferenceLoader}
 * — i.e. a per-object {@code @ExternalAuthorization(<KIND>, DETAIL)} entrypoint taking a {@code SecuredUUID}.
 * <p>
 * Kinds absent from the map (CERTIFICATE, SECRET) have no caller-side connector-consumable blob to expand and are
 * passed through as plain references by {@link AttributeReferenceExpander}. SECRET's inline content is the
 * connector's responsibility, not Core's to expand; a credential's stored material reaches the wire only through
 * the CREDENTIAL loader below, never by re-fetching a user-typed SECRET value.
 * <p>
 * Each value is a method reference onto the guarded service method, so this class never references an unguarded
 * by-UUID primitive itself — the wiring stays inside the type-level fence.
 */
@Component
public class CallerAuthorizedReferenceLoaderRegistry {

    private final Map<AttributeResource, CallerAuthorizedReferenceLoader> loaders =
            new EnumMap<>(AttributeResource.class);

    public CallerAuthorizedReferenceLoaderRegistry(CredentialInternalService credentialService,
                                                   AuthorityInstanceInternalService authorityService,
                                                   EntityInstanceInternalService entityService,
                                                   LocationInternalService locationService) {
        loaders.put(AttributeResource.CREDENTIAL, credentialService::getAuthorizedObjectAttributes);
        loaders.put(AttributeResource.AUTHORITY, authorityService::getAuthorizedObjectAttributes);
        loaders.put(AttributeResource.ENTITY, entityService::getAuthorizedObjectAttributes);
        loaders.put(AttributeResource.LOCATION, locationService::getAuthorizedObjectAttributes);
    }

    /**
     * @return the per-object guarded loader for {@code kind}, or {@code null} when the kind has no
     * connector-consumable blob (pass-through reference).
     */
    CallerAuthorizedReferenceLoader loaderFor(AttributeResource kind) {
        return loaders.get(kind);
    }
}
