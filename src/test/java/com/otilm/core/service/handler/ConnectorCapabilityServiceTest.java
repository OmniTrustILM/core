package com.otilm.core.service.handler;

import com.otilm.api.model.client.connector.v2.ConnectorInterface;
import com.otilm.api.model.client.connector.v2.FeatureFlag;
import com.otilm.core.dao.entity.AuthorityInstanceReference;
import com.otilm.core.dao.entity.ConnectorInterfaceEntity;
import org.junit.jupiter.api.Test;

import java.util.List;

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
    void enforcedFlagSupportedOnlyWhenAdvertised() {
        assertTrue(service.supports(
                authorityWith(authorityInterface("v3", List.of(FeatureFlag.CERTIFICATE_REGISTRATION))),
                FeatureFlag.CERTIFICATE_REGISTRATION));
        assertFalse(service.supports(
                authorityWith(authorityInterface("v3", List.of())),
                FeatureFlag.CERTIFICATE_REGISTRATION));
    }

    @Test
    void informationalFlagAlwaysPassesThrough() {
        // STATELESS is INFORMATIONAL — supported even though it is not advertised.
        assertTrue(service.supports(
                authorityWith(authorityInterface("v3", List.of())),
                FeatureFlag.STATELESS));
    }

    @Test
    void enforcedFlagUnsupportedWhenAuthorityInterfaceOrFeaturesMissing() {
        assertFalse(service.supports((AuthorityInstanceReference) null, FeatureFlag.CERTIFICATE_REGISTRATION));
        assertFalse(service.supports(authorityWith(null), FeatureFlag.CERTIFICATE_REGISTRATION));
        assertFalse(service.supports(authorityWith(authorityInterface("v3", null)), FeatureFlag.CERTIFICATE_REGISTRATION));
    }
}
