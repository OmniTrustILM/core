package com.otilm.core.attribute.engine;

import com.otilm.api.model.core.auth.AttributeResource;
import com.otilm.core.service.AuthorityInstanceInternalService;
import com.otilm.core.service.CredentialInternalService;
import com.otilm.core.service.EntityInstanceInternalService;
import com.otilm.core.service.LocationInternalService;
import com.otilm.core.service.SecretInternalService;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.mockito.Mockito.mock;

/**
 * Guards which {@code AttributeResource} kinds the callback-mode expander will dereference. A missing kind here
 * silently downgrades to a bare-reference pass-through, which for a stateless connector means an unusable
 * reference on the wire (e.g. an authority's {@code oauthClient}, a stored Basic-Auth SECRET reference).
 */
class CallerAuthorizedReferenceLoaderRegistryTest {

    private CallerAuthorizedReferenceLoaderRegistry registry() {
        return new CallerAuthorizedReferenceLoaderRegistry(
                mock(CredentialInternalService.class),
                mock(AuthorityInstanceInternalService.class),
                mock(EntityInstanceInternalService.class),
                mock(LocationInternalService.class),
                mock(SecretInternalService.class));
    }

    @Test
    void registersSecretLoader() {
        assertNotNull(registry().loaderFor(AttributeResource.SECRET),
                "SECRET must have a caller-authorized loader so stored SECRET references are dereferenced, not passed through");
    }

    @Test
    void registersTheFourObjectConfigKinds() {
        CallerAuthorizedReferenceLoaderRegistry r = registry();
        assertNotNull(r.loaderFor(AttributeResource.CREDENTIAL));
        assertNotNull(r.loaderFor(AttributeResource.AUTHORITY));
        assertNotNull(r.loaderFor(AttributeResource.ENTITY));
        assertNotNull(r.loaderFor(AttributeResource.LOCATION));
    }

    @Test
    void certificateStaysPassThrough() {
        // CERTIFICATE carries no connector-consumable blob to dereference; it must remain a null (pass-through) loader.
        assertNull(registry().loaderFor(AttributeResource.CERTIFICATE));
    }
}
