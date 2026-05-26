package com.czertainly.core.service.handler;

import com.czertainly.api.model.client.connector.v2.ConnectorInterface;
import com.czertainly.api.model.client.connector.v2.FeatureFlag;
import com.czertainly.core.dao.entity.AuthorityInstanceReference;
import com.czertainly.core.dao.entity.Connector;
import com.czertainly.core.dao.entity.ConnectorInterfaceEntity;
import org.springframework.stereotype.Service;

/**
 * Gate for connector capability checks. Generic across provider interfaces — reusable
 * for future cryptography v3, secret v3, etc.
 *
 * <p>Opt-in semantic for ENFORCED FeatureFlags: absent flag = unsupported.
 * INFORMATIONAL flags are advertisement-only and always return true (Core handles all
 * behaviors regardless of advertisement).</p>
 */
@Service
public class ConnectorCapabilityService {

    public boolean supports(Connector connector, ConnectorInterface iface, FeatureFlag flag) {
        if (flag.getBehavior() == FeatureFlag.FeatureFlagBehavior.INFORMATIONAL) {
            return true;
        }
        return connector.getInterfaces().stream()
            .filter(i -> i.getInterfaceCode() == iface)
            .findFirst()
            .map(i -> i.getFeatures() != null && i.getFeatures().contains(flag))
            .orElse(false);
    }

    public boolean supports(AuthorityInstanceReference authority, FeatureFlag flag) {
        if (flag.getBehavior() == FeatureFlag.FeatureFlagBehavior.INFORMATIONAL) {
            return true;
        }
        ConnectorInterfaceEntity iface = authority.getConnectorInterface();
        return iface != null && iface.getFeatures() != null && iface.getFeatures().contains(flag);
    }
}
