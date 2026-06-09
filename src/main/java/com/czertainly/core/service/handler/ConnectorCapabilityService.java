package com.czertainly.core.service.handler;

import com.otilm.api.model.client.connector.v2.ConnectorInterface;
import com.otilm.api.model.client.connector.v2.FeatureFlag;
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

    /**
     * Connector-level capability check. Picks the FIRST {@link ConnectorInterfaceEntity}
     * matching {@code iface} via JPA collection iteration order — this is non-deterministic
     * when a connector exposes multiple rows for the same interface code (e.g. AUTHORITY
     * v2 + AUTHORITY v3 side-by-side). Callers that need per-version capability checks
     * MUST use the {@link #supports(Connector, ConnectorInterface, String, FeatureFlag)}
     * overload instead. Today the only production caller is the {@link AuthorityInstanceReference}
     * variant below, which uses the authority's specific interface; this overload remains
     * for future generic callers (discovery, admin UI) and should not be used for routing
     * decisions on multi-version connectors.
     */
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

    /**
     * Version-disambiguated capability check. Prefer this overload over
     * {@link #supports(Connector, ConnectorInterface, FeatureFlag)} when the caller knows
     * which version it cares about. Returns false if no matching (iface, version) row exists.
     */
    public boolean supports(Connector connector, ConnectorInterface iface, String version, FeatureFlag flag) {
        if (flag.getBehavior() == FeatureFlag.FeatureFlagBehavior.INFORMATIONAL) {
            return true;
        }
        return connector.getInterfaces().stream()
            .filter(i -> i.getInterfaceCode() == iface && java.util.Objects.equals(i.getVersion(), version))
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
