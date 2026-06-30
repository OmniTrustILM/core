package com.otilm.core.service.handler;

import com.otilm.api.model.client.connector.v2.FeatureFlag;
import com.otilm.api.model.client.connector.v2.FeatureFlag.FeatureFlagBehavior;
import com.otilm.core.dao.entity.AuthorityInstanceReference;
import com.otilm.core.dao.entity.ConnectorInterfaceEntity;
import org.springframework.stereotype.Service;

/**
 * Service-layer capability gate — defense-in-depth layer 2 between the protocol-level
 * {@code instanceof <Capability>} check (layer 1) and the connector-side {@code OPERATION_NOT_SUPPORTED}
 * runtime error (layer 3).
 *
 * <p>Resolves whether a connector advertises a {@link FeatureFlag} on the relevant interface:
 * <ul>
 *   <li><b>ENFORCED</b> flags are opt-in — supported only when the connector explicitly advertises
 *       the flag on the applicable interface; absent means unsupported.</li>
 *   <li><b>INFORMATIONAL</b> flags pass through — Core handles the behavior regardless of whether it
 *       is advertised, so {@code supports(...)} is always true.</li>
 * </ul>
 *
 * <p>The ENFORCED/INFORMATIONAL gate is generic over any {@link FeatureFlag}; the current entry point
 * resolves per authority instance.
 */
@Service
public class ConnectorCapabilityService {

    /** Per-authority check — reads the authority's own bound interface entity directly, so it is
     *  correct even when the connector exposes multiple versions of the AUTHORITY interface. */
    public boolean supports(AuthorityInstanceReference authority, FeatureFlag flag) {
        if (flag.getBehavior() == FeatureFlagBehavior.INFORMATIONAL) {
            return true;
        }
        return authority != null && advertises(authority.getConnectorInterface(), flag);
    }

    private static boolean advertises(ConnectorInterfaceEntity iface, FeatureFlag flag) {
        return iface != null && iface.getFeatures() != null && iface.getFeatures().contains(flag);
    }
}
