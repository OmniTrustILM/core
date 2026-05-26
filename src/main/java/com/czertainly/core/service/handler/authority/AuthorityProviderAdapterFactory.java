package com.czertainly.core.service.handler.authority;

import com.czertainly.core.dao.entity.AuthorityInstanceReference;
import com.czertainly.core.dao.entity.ConnectorInterfaceEntity;
import com.czertainly.core.exception.UnsupportedAuthorityVersionException;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

/**
 * Dispatches authority operations to the adapter matching the authority's connector interface
 * version. v2 → {@link AuthorityProviderV2Adapter}, v3 → {@link AuthorityProviderV3Adapter}.
 *
 * <p>Defensive — v1 authorities flow through the legacy v1 service path and never reach this
 * factory. If a v1 (or unrecognized) version is encountered, throws
 * {@link UnsupportedAuthorityVersionException}.</p>
 *
 * <p>{@link ConnectorInterfaceEntity#getVersion()} returns the version string as reported by the
 * connector's info endpoint (e.g. {@code "v2"}, {@code "v3"}). The factory matches on those
 * prefixed string values; any other value, including {@code null} or the bare decimal {@code "2"},
 * results in an {@link UnsupportedAuthorityVersionException}.</p>
 */
@Component
public class AuthorityProviderAdapterFactory {

    private final AuthorityProviderV2Adapter v2Adapter;
    private final AuthorityProviderV3Adapter v3Adapter;

    @Autowired
    public AuthorityProviderAdapterFactory(AuthorityProviderV2Adapter v2Adapter,
                                           AuthorityProviderV3Adapter v3Adapter) {
        this.v2Adapter = v2Adapter;
        this.v3Adapter = v3Adapter;
    }

    public AuthorityProviderAdapter forAuthority(AuthorityInstanceReference authority) {
        ConnectorInterfaceEntity iface = authority.getConnectorInterface();
        if (iface == null) {
            // Connector declared no AUTHORITY interface row in connector_interface. This is
            // expected for framework-v1 connectors that implement the v2 authority wire
            // protocol (e.g. ejbca-ng) — their /v1/info endpoint predates the v2 interface
            // descriptor and the M0 backfill cannot create a row for them. Route to v2
            // since that is the wire protocol they speak. Legacy v1-authority connectors
            // (FunctionGroupCode.LEGACY_AUTHORITY_PROVIDER) never reach this factory; they
            // route through the separate legacy service path by design.
            return v2Adapter;
        }
        String version = iface.getVersion();
        return switch (version) {
            case "v2" -> v2Adapter;
            case "v3" -> v3Adapter;
            default -> throw new UnsupportedAuthorityVersionException(
                    "Unsupported authority connector interface version: " + version
                            + " (authority " + authority.getUuid() + ")");
        };
    }
}
