package com.otilm.core.service;

import com.otilm.api.exception.NotSupportedException;
import com.otilm.core.security.authz.SecuredUUID;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;

import java.util.UUID;

import static org.junit.jupiter.api.Assertions.assertThrows;

class ResourceExtensionServiceTest {

    @Test
    void defaultAuthorizedObjectAttributesLoaderRefuses() {
        // A kind without a connector-consumable blob loader must refuse via the interface default (fail-closed),
        // not silently return. CALLS_REAL_METHODS invokes the real default body.
        ResourceExtensionService service =
                Mockito.mock(ResourceExtensionService.class, Mockito.CALLS_REAL_METHODS);
        assertThrows(NotSupportedException.class,
                () -> service.getAuthorizedObjectAttributes(SecuredUUID.fromUUID(UUID.randomUUID())));
    }
}
