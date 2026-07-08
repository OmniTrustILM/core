package com.otilm.core.attribute.engine;

import com.otilm.api.model.core.auth.AttributeResource;
import com.otilm.core.service.AuthorityInstanceInternalService;
import com.otilm.core.service.CredentialInternalService;
import com.otilm.core.service.EntityInstanceInternalService;
import com.otilm.core.service.LocationInternalService;
import com.otilm.core.service.SecretInternalService;
import org.springframework.stereotype.Component;

import java.util.EnumMap;
import java.util.Map;

/**
 * Typed {@code AttributeResource -> SecuredUUID-guarded loader} registry. Callback-mode
 * expansion resolves <strong>only</strong> through this map, and every value is a {@link CallerAuthorizedReferenceLoader}
 * — i.e. a per-object guarded entrypoint taking a {@code SecuredUUID}.
 * <p>
 * CREDENTIAL/AUTHORITY/ENTITY/LOCATION resolve via {@code <KIND>:DETAIL}; SECRET resolves via
 * {@code SECRET:GET_SECRET_CONTENT} plus vault-profile membership (the established secret-content gate). SECRET is
 * dereferenced because a <strong>stored</strong> SECRET reference carried in a scope blob (for example an
 * authority's OAuth-client secret) is unusable to a stateless connector as a bare reference — Core must resolve it.
 * This is distinct from a <strong>user-typed</strong> secret in {@code currentAttributes}, which is an inline
 * first-delivery value (not a {@code ResourceObjectContent} reference) and so is never walked by the expander.
 * <p>
 * CERTIFICATE stays absent (no connector-consumable blob) and is passed through as a plain reference.
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
                                                   LocationInternalService locationService,
                                                   SecretInternalService secretService) {
        loaders.put(AttributeResource.CREDENTIAL, credentialService::getAuthorizedObjectAttributes);
        loaders.put(AttributeResource.AUTHORITY, authorityService::getAuthorizedObjectAttributes);
        loaders.put(AttributeResource.ENTITY, entityService::getAuthorizedObjectAttributes);
        loaders.put(AttributeResource.LOCATION, locationService::getAuthorizedObjectAttributes);
        loaders.put(AttributeResource.SECRET, secretService::getAuthorizedObjectAttributes);
    }

    /**
     * @return the per-object guarded loader for {@code kind}, or {@code null} when the kind has no
     * connector-consumable blob (pass-through reference).
     */
    CallerAuthorizedReferenceLoader loaderFor(AttributeResource kind) {
        return loaders.get(kind);
    }
}
