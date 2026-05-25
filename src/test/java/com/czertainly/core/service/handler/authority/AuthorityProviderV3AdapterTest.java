package com.czertainly.core.service.handler.authority;

import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

class AuthorityProviderV3AdapterTest {

    private final AuthorityProviderV3Adapter adapter = new AuthorityProviderV3Adapter();

    @Test
    void issueThrowsNotYetImplemented() {
        UnsupportedOperationException ex = assertThrows(
                UnsupportedOperationException.class,
                () -> adapter.issue(null, null));
        assertEquals("v3 adapter not yet implemented", ex.getMessage());
    }

    @Test
    void implementsRegisterCapability() {
        assertTrue(adapter instanceof RegisterCapability);
    }

    @Test
    void implementsAsyncOperationCapability() {
        assertTrue(adapter instanceof AsyncOperationCapability);
    }
}
