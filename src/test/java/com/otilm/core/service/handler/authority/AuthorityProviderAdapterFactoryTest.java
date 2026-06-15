package com.otilm.core.service.handler.authority;

import com.otilm.core.dao.entity.AuthorityInstanceReference;
import com.otilm.core.dao.entity.ConnectorInterfaceEntity;
import com.otilm.core.exception.UnsupportedAuthorityVersionException;
import org.junit.jupiter.api.Test;

import java.util.UUID;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

class AuthorityProviderAdapterFactoryTest {

    private final AuthorityProviderV2Adapter v2 = mock(AuthorityProviderV2Adapter.class);
    private final AuthorityProviderV3Adapter v3 = mock(AuthorityProviderV3Adapter.class);
    private final AuthorityProviderAdapterFactory factory = new AuthorityProviderAdapterFactory(v2, v3);

    @Test
    void dispatchesV2() {
        assertSame(v2, factory.forAuthority(authorityWithVersion("v2")));
    }

    @Test
    void dispatchesV3() {
        assertSame(v3, factory.forAuthority(authorityWithVersion("v3")));
    }

    @Test
    void rejectsV1() {
        AuthorityInstanceReference auth = authorityWithVersion("v1");
        UnsupportedAuthorityVersionException ex = assertThrows(
                UnsupportedAuthorityVersionException.class,
                () -> factory.forAuthority(auth));
        assertTrue(ex.getMessage().contains("v1"));
    }

    @Test
    void rejectsNullVersion() {
        // A non-null connector interface carrying a null version is malformed; the factory throws
        // (rather than NPE on the switch). Distinct from the null-interface fallback below.
        AuthorityInstanceReference auth = authorityWithVersion(null);
        assertThrows(UnsupportedAuthorityVersionException.class, () -> factory.forAuthority(auth));
    }

    @Test
    void missingInterfaceFallsBackToV2() {
        // A null connector interface is expected for framework-v1 connectors that implement the
        // v2 authority wire protocol (e.g. ejbca-ng) — they declare no connector_interface row,
        // so the M0 backfill leaves the FK null. The factory routes these to the v2 adapter
        // (the protocol they speak). Legacy v1-authority connectors never reach this factory.
        AuthorityInstanceReference auth = new AuthorityInstanceReference();
        auth.setUuid(UUID.randomUUID());
        // connector interface left null
        assertSame(v2, factory.forAuthority(auth));
    }

    /**
     * @param version connector-format version string, e.g. {@code "v2"}, {@code "v3"}, {@code "v1"}.
     *                Must include the {@code v} prefix — that is the format stored by
     *                {@link com.otilm.core.service.handler.ConnectorV2Adapter} from the
     *                connector's info endpoint.
     */
    private AuthorityInstanceReference authorityWithVersion(String version) {
        AuthorityInstanceReference auth = new AuthorityInstanceReference();
        auth.setUuid(UUID.randomUUID());
        ConnectorInterfaceEntity iface = new ConnectorInterfaceEntity();
        iface.setVersion(version);
        auth.setConnectorInterface(iface);
        return auth;
    }
}
