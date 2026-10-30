package com.otilm.core.service.handler;

import com.otilm.api.model.client.connector.v2.ConnectorInterface;
import com.otilm.api.model.client.connector.v2.FeatureFlag;
import com.otilm.core.dao.entity.AuthorityInstanceReference;
import com.otilm.core.dao.entity.ConnectorInterfaceEntity;
import com.otilm.core.model.connector.ImmutableConnectorInterface;
import java.util.List;
import java.util.UUID;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class ConnectorCapabilityServiceTest {

    private final ConnectorCapabilityService service = new ConnectorCapabilityService();

    private ConnectorInterfaceEntity authorityInterface(String version, List<FeatureFlag> features) {
        ConnectorInterfaceEntity iface = new ConnectorInterfaceEntity();
        iface.setInterfaceCode(ConnectorInterface.AUTHORITY);
        iface.setVersion(version);
        iface.setFeatures(features);
        return iface;
    }

    private AuthorityInstanceReference authorityWith(ConnectorInterfaceEntity iface) {
        AuthorityInstanceReference authority = new AuthorityInstanceReference();
        authority.setConnectorInterface(iface);
        return authority;
    }

    @Test
    void snapshotOverloadReadsTheFeaturesTheModelCarries() {
        ImmutableConnectorInterface advertising = snapshot(List.of(FeatureFlag.KEY_EXPORT));
        ImmutableConnectorInterface silent = snapshot(List.of());

        assertTrue(service.supports(advertising, FeatureFlag.KEY_EXPORT));
        assertFalse(service.supports(silent, FeatureFlag.KEY_EXPORT));
        assertFalse(service.supports((ImmutableConnectorInterface) null, FeatureFlag.KEY_EXPORT));
    }

    @Test
    void snapshotOverloadPassesInformationalFlagsThrough() {
        assertTrue(service.supports(snapshot(List.of()), FeatureFlag.STATELESS));
    }

    private ImmutableConnectorInterface snapshot(List<FeatureFlag> features) {
        return new ImmutableConnectorInterface(UUID.randomUUID(), ConnectorInterface.CRYPTOGRAPHY, "v2", features);
    }

    @Test
    void enforcedFlagSupportedOnlyWhenAdvertised() {
        assertTrue(service
                .supports(authorityWith(authorityInterface("v3", List.of(FeatureFlag.CERTIFICATE_REGISTRATION))),
                        FeatureFlag.CERTIFICATE_REGISTRATION));
        assertFalse(service
                .supports(authorityWith(authorityInterface("v3", List.of())), FeatureFlag.CERTIFICATE_REGISTRATION));
    }

    @Test
    void informationalFlagAlwaysPassesThrough() {
        // STATELESS is INFORMATIONAL — supported even though it is not advertised.
        assertTrue(service.supports(authorityWith(authorityInterface("v3", List.of())), FeatureFlag.STATELESS));
    }

    @Test
    void enforcedFlagUnsupportedWhenAuthorityInterfaceOrFeaturesMissing() {
        assertFalse(service.supports((AuthorityInstanceReference) null, FeatureFlag.CERTIFICATE_REGISTRATION));
        assertFalse(service.supports(authorityWith(null), FeatureFlag.CERTIFICATE_REGISTRATION));
        assertFalse(
                service.supports(authorityWith(authorityInterface("v3", null)), FeatureFlag.CERTIFICATE_REGISTRATION));
    }

    private ConnectorInterfaceEntity discoveryInterface(List<FeatureFlag> features) {
        ConnectorInterfaceEntity iface = new ConnectorInterfaceEntity();
        iface.setInterfaceCode(ConnectorInterface.DISCOVERY);
        iface.setVersion("v2");
        iface.setFeatures(features);
        return iface;
    }

    @Test
    void interfaceRowKeyedEnforcedFlagSupportedOnlyWhenAdvertised() {
        assertTrue(service
                .supports(discoveryInterface(List.of(FeatureFlag.DISCOVERY_STOP_RESUME)),
                        FeatureFlag.DISCOVERY_STOP_RESUME));
        assertFalse(service.supports(discoveryInterface(List.of()), FeatureFlag.DISCOVERY_STOP_RESUME));
    }

    @Test
    void interfaceRowKeyedInformationalFlagAlwaysPassesThrough() {
        assertTrue(service.supports(discoveryInterface(List.of()), FeatureFlag.STATELESS));
    }

    @Test
    void interfaceRowKeyedEnforcedFlagUnsupportedWhenRowOrFeaturesMissing() {
        assertFalse(service.supports((ConnectorInterfaceEntity) null, FeatureFlag.DISCOVERY_STOP_RESUME));
        assertFalse(service.supports(discoveryInterface(null), FeatureFlag.DISCOVERY_STOP_RESUME));
    }
}
