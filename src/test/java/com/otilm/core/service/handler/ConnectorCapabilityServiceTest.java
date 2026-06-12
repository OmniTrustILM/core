package com.otilm.core.service.handler;

import com.otilm.api.model.client.connector.v2.ConnectorInterface;
import com.otilm.api.model.client.connector.v2.FeatureFlag;
import com.otilm.core.dao.entity.AuthorityInstanceReference;
import com.otilm.core.dao.entity.Connector;
import com.otilm.core.dao.entity.ConnectorInterfaceEntity;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class ConnectorCapabilityServiceTest {

    private final ConnectorCapabilityService service = new ConnectorCapabilityService();

    @Test
    void enforcedFlagReturnsTrueWhenAdvertised() {
        AuthorityInstanceReference auth = authorityWithFeatures(FeatureFlag.CERTIFICATE_REGISTRATION);
        assertTrue(service.supports(auth, FeatureFlag.CERTIFICATE_REGISTRATION));
    }

    @Test
    void enforcedFlagReturnsFalseWhenAbsent() {
        AuthorityInstanceReference auth = authorityWithFeatures();
        assertFalse(service.supports(auth, FeatureFlag.CERTIFICATE_REGISTRATION));
    }

    @Test
    void informationalFlagAlwaysReturnsTrue() {
        AuthorityInstanceReference authNo = authorityWithFeatures();
        AuthorityInstanceReference authYes = authorityWithFeatures(FeatureFlag.STATELESS);
        assertTrue(service.supports(authNo, FeatureFlag.STATELESS));
        assertTrue(service.supports(authYes, FeatureFlag.STATELESS));
    }

    @Test
    void nullFeaturesListTreatedAsEmpty() {
        AuthorityInstanceReference auth = authorityWithFeaturesNull();
        assertFalse(service.supports(auth, FeatureFlag.CERTIFICATE_REGISTRATION));
    }

    private AuthorityInstanceReference authorityWithFeatures(FeatureFlag... flags) {
        return buildAuthorityWith(List.of(flags));
    }

    private AuthorityInstanceReference authorityWithFeaturesNull() {
        return buildAuthorityWith(null);
    }

    private AuthorityInstanceReference buildAuthorityWith(List<FeatureFlag> features) {
        Connector connector = mock(Connector.class);
        ConnectorInterfaceEntity iface = new ConnectorInterfaceEntity();
        iface.setInterfaceCode(ConnectorInterface.AUTHORITY);
        iface.setFeatures(features);
        when(connector.getInterfaces()).thenReturn(Set.of(iface));
        iface.setConnector(connector);

        AuthorityInstanceReference ai = new AuthorityInstanceReference();
        ai.setConnectorInterface(iface);
        return ai;
    }
}
